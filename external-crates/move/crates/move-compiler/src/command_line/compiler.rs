// Copyright (c) The Diem Core Contributors
// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use crate::{
    cfgir::{self, visitor::AbsIntVisitorObj},
    command_line::{DEFAULT_OUTPUT_DIR, MOVE_COMPILED_INTERFACES_DIR},
    compiled_unit,
    compiled_unit::AnnotatedCompiledUnit,
    diagnostics::{
        codes::{Severity, WarningFilter},
        *,
    },
    editions::Edition,
    expansion, hlir, interface_generator, naming, parser,
    parser::{comments::*, *},
    shared::{
        CompilationEnv, Flags, IndexedPhysicalPackagePath, IndexedVfsPackagePath, NamedAddressMap,
        NamedAddressMaps, NumericalAddress, PackageConfig, PackagePaths,
    },
    to_bytecode,
    typing::{self, visitor::TypingVisitorObj},
    unit_test,
};
use move_command_line_common::files::{
    find_filenames_vfs, MOVE_COMPILED_EXTENSION, MOVE_EXTENSION, SOURCE_MAP_EXTENSION,
};
use move_core_types::language_storage::ModuleId as CompiledModuleId;
use move_proc_macros::growing_stack;
use move_symbol_pool::Symbol;
use pathdiff::diff_paths;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::PathBuf,
};
use vfs::{
    impls::{memory::MemoryFS, physical::PhysicalFS},
    path::VfsFileType,
    VfsPath,
};

//**************************************************************************************************
// Definitions
//**************************************************************************************************

pub struct Compiler<'a> {
    maps: NamedAddressMaps,
    targets: Vec<IndexedPhysicalPackagePath>,
    deps: Vec<IndexedPhysicalPackagePath>,
    interface_files_dir_opt: Option<String>,
    pre_compiled_lib: Option<&'a FullyCompiledProgram>,
    compiled_module_named_address_mapping: BTreeMap<CompiledModuleId, String>,
    flags: Flags,
    visitors: Vec<Visitor>,
    /// Predefined filter for compiler warnings.
    warning_filter: Option<WarningFilters>,
    known_warning_filters: Vec<(/* Prefix */ Option<Symbol>, Vec<WarningFilter>)>,
    package_configs: BTreeMap<Symbol, PackageConfig>,
    default_config: Option<PackageConfig>,
    /// Root path of the virtual file system.
    vfs_root: Option<VfsPath>,
}

pub struct SteppedCompiler<'a, const P: Pass> {
    compilation_env: CompilationEnv,
    pre_compiled_lib: Option<&'a FullyCompiledProgram>,
    program: Option<PassResult>,
}

pub type Pass = u8;
pub const EMPTY_COMPILER: Pass = 0;
pub const PASS_PARSER: Pass = 1;
pub const PASS_EXPANSION: Pass = 2;
pub const PASS_NAMING: Pass = 3;
pub const PASS_TYPING: Pass = 4;
pub const PASS_HLIR: Pass = 5;
pub const PASS_CFGIR: Pass = 6;
pub const PASS_COMPILATION: Pass = 7;

#[derive(Debug)]
enum PassResult {
    Parser(parser::ast::Program),
    Expansion(expansion::ast::Program),
    Naming(naming::ast::Program),
    Typing(typing::ast::Program),
    HLIR(hlir::ast::Program),
    CFGIR(cfgir::ast::Program),
    Compilation(Vec<AnnotatedCompiledUnit>, /* warnings */ Diagnostics),
}

#[derive(Clone)]
pub struct FullyCompiledProgram {
    // TODO don't store this...
    pub files: FilesSourceText,
    pub parser: parser::ast::Program,
    pub expansion: expansion::ast::Program,
    pub naming: naming::ast::Program,
    pub typing: typing::ast::Program,
    pub hlir: hlir::ast::Program,
    pub cfgir: cfgir::ast::Program,
    pub compiled: Vec<AnnotatedCompiledUnit>,
}

pub enum Visitor {
    TypingVisitor(TypingVisitorObj),
    AbsIntVisitor(AbsIntVisitorObj),
}

//**************************************************************************************************
// Entry points and impls
//**************************************************************************************************

impl<'a> Compiler<'a> {
    pub fn from_package_paths<Paths: Into<Symbol>, NamedAddress: Into<Symbol>>(
        targets: Vec<PackagePaths<Paths, NamedAddress>>,
        deps: Vec<PackagePaths<Paths, NamedAddress>>,
    ) -> anyhow::Result<Self> {
        fn indexed_scopes(
            maps: &mut NamedAddressMaps,
            package_configs: &mut BTreeMap<Symbol, PackageConfig>,
            all_pkgs: Vec<PackagePaths<impl Into<Symbol>, impl Into<Symbol>>>,
        ) -> anyhow::Result<Vec<IndexedPhysicalPackagePath>> {
            let mut idx_paths = vec![];
            for PackagePaths {
                name,
                paths,
                named_address_map,
            } in all_pkgs
            {
                let name = if let Some((name, config)) = name {
                    let prev = package_configs.insert(name, config);
                    anyhow::ensure!(prev.is_none(), "Duplicate package entry for '{name}'");
                    Some(name)
                } else {
                    None
                };
                let idx = maps.insert(
                    named_address_map
                        .into_iter()
                        .map(|(k, v)| (k.into(), v))
                        .collect::<NamedAddressMap>(),
                );
                idx_paths.extend(paths.into_iter().map(|path| IndexedPhysicalPackagePath {
                    package: name,
                    path: path.into(),
                    named_address_map: idx,
                }))
            }
            Ok(idx_paths)
        }
        let mut maps = NamedAddressMaps::new();
        let mut package_configs = BTreeMap::new();
        let targets = indexed_scopes(&mut maps, &mut package_configs, targets)?;
        let deps = indexed_scopes(&mut maps, &mut package_configs, deps)?;

        Ok(Self {
            maps,
            targets,
            deps,
            interface_files_dir_opt: None,
            pre_compiled_lib: None,
            compiled_module_named_address_mapping: BTreeMap::new(),
            flags: Flags::empty(),
            visitors: vec![],
            warning_filter: None,
            known_warning_filters: vec![],
            package_configs,
            default_config: None,
            vfs_root: None,
        })
    }

    pub fn from_files<Paths: Into<Symbol>, NamedAddress: Into<Symbol> + Clone>(
        targets: Vec<Paths>,
        deps: Vec<Paths>,
        named_address_map: BTreeMap<NamedAddress, NumericalAddress>,
    ) -> Self {
        let targets = vec![PackagePaths {
            name: None,
            paths: targets,
            named_address_map: named_address_map.clone(),
        }];
        let deps = vec![PackagePaths {
            name: None,
            paths: deps,
            named_address_map,
        }];
        Self::from_package_paths(targets, deps).unwrap()
    }

    pub fn set_flags(mut self, flags: Flags) -> Self {
        assert!(self.flags.is_empty());
        self.flags = flags;
        self
    }

    pub fn set_interface_files_dir(mut self, dir: String) -> Self {
        assert!(self.interface_files_dir_opt.is_none());
        self.interface_files_dir_opt = Some(dir);
        self
    }

    pub fn set_interface_files_dir_opt(mut self, dir_opt: Option<String>) -> Self {
        assert!(self.interface_files_dir_opt.is_none());
        self.interface_files_dir_opt = dir_opt;
        self
    }

    pub fn set_pre_compiled_lib(mut self, pre_compiled_lib: &'a FullyCompiledProgram) -> Self {
        assert!(self.pre_compiled_lib.is_none());
        self.pre_compiled_lib = Some(pre_compiled_lib);
        self
    }

    pub fn set_pre_compiled_lib_opt(
        mut self,
        pre_compiled_lib: Option<&'a FullyCompiledProgram>,
    ) -> Self {
        assert!(self.pre_compiled_lib.is_none());
        self.pre_compiled_lib = pre_compiled_lib;
        self
    }

    pub fn set_compiled_module_named_address_mapping(
        mut self,
        compiled_module_named_address_mapping: BTreeMap<CompiledModuleId, String>,
    ) -> Self {
        assert!(self.compiled_module_named_address_mapping.is_empty());
        self.compiled_module_named_address_mapping = compiled_module_named_address_mapping;
        self
    }

    pub fn add_visitor(mut self, pass: impl Into<Visitor>) -> Self {
        self.visitors.push(pass.into());
        self
    }

    pub fn add_visitors(mut self, passes: impl IntoIterator<Item = Visitor>) -> Self {
        self.visitors.extend(passes);
        self
    }

    pub fn set_warning_filter(mut self, filter: Option<WarningFilters>) -> Self {
        assert!(self.warning_filter.is_none());
        self.warning_filter = filter;
        self
    }

    /// `prefix` is None for the default 'allow'.
    /// Some(prefix) for a custom set of warnings, e.g. 'allow(lint(_))'.
    pub fn add_custom_known_filters(
        mut self,
        prefix: Option<impl Into<Symbol>>,
        filters: Vec<WarningFilter>,
    ) -> Self {
        self.known_warning_filters
            .push((prefix.map(|s| s.into()), filters));
        self
    }

    /// Sets the PackageConfig for files without a specified package
    pub fn set_default_config(mut self, config: PackageConfig) -> Self {
        assert!(self.default_config.is_none());
        self.default_config = Some(config);
        self
    }

    pub fn set_vfs_root(mut self, vfs_root: VfsPath) -> Self {
        assert!(self.vfs_root.is_none());
        self.vfs_root = Some(vfs_root);
        self
    }

    pub fn run<const TARGET: Pass>(
        self,
    ) -> anyhow::Result<(
        FilesSourceText,
        Result<(CommentMap, SteppedCompiler<'a, TARGET>), (Pass, Diagnostics)>,
    )> {
        /// Path relativization after parsing is needed as paths are initially canonicalized when
        /// converted to virtual file system paths and would show up as absolute in the test output
        /// which wouldn't be machine-agnostic. We need to relativize using `vfs_root` beacuse it
        /// was also used during canonicalization and might have altered path prefix in a
        /// non-standard way (e.g., this can happen on Windows).
        fn relativize_path(vsf_root: &VfsPath, path: Symbol) -> Symbol {
            let Some(current_dir) = std::env::current_dir().ok() else {
                return path;
            };
            let Ok(current_dir_vfs) = vsf_root.join(current_dir.to_string_lossy()) else {
                return path;
            };
            let Some(new_path) = diff_paths(path.to_string(), current_dir_vfs.as_str()) else {
                return path;
            };
            Symbol::from(new_path.to_string_lossy().to_string())
        }

        let Self {
            maps,
            targets,
            deps,
            interface_files_dir_opt,
            pre_compiled_lib,
            compiled_module_named_address_mapping,
            flags,
            visitors,
            warning_filter,
            known_warning_filters,
            package_configs,
            default_config,
            vfs_root,
        } = self;
        let vfs_root = match vfs_root {
            Some(p) => p,
            None => VfsPath::new(PhysicalFS::new("/")),
        };

        let targets = targets
            .into_iter()
            .map(|p| Ok(p.to_vfs_path(&vfs_root)?))
            .collect::<Result<Vec<_>, anyhow::Error>>()?;

        let mut deps = deps
            .into_iter()
            .map(|p| Ok(p.to_vfs_path(&vfs_root)?))
            .collect::<Result<Vec<_>, anyhow::Error>>()?;

        generate_interface_files_for_deps(
            &mut deps,
            interface_files_dir_opt,
            &compiled_module_named_address_mapping,
        )?;
        let mut compilation_env =
            CompilationEnv::new(flags, visitors, package_configs, default_config);
        if let Some(filter) = warning_filter {
            compilation_env.add_warning_filter_scope(filter);
        }
        for (prefix, filters) in known_warning_filters {
            compilation_env.add_custom_known_filters(prefix, filters)?;
        }

        let (mut source_text, pprog, comments) =
            parse_program(&mut compilation_env, maps, targets, deps)?;

        source_text
            .iter_mut()
            .for_each(|(_, (path, _))| *path = relativize_path(&vfs_root, *path));

        source_text.iter().for_each(|(fhash, (fname, contents))| {
            compilation_env.add_source_file(*fhash, *fname, contents.clone())
        });

        let res: Result<_, (Pass, Diagnostics)> =
            SteppedCompiler::new_at_parser(compilation_env, pre_compiled_lib, pprog)
                .run::<TARGET>()
                .map(|compiler| (comments, compiler));

        Ok((source_text, res))
    }

    pub fn generate_migration_patch(
        mut self,
        root_module: &Symbol,
    ) -> anyhow::Result<(FilesSourceText, Result<Option<Migration>, Diagnostics>)> {
        self.package_configs.get_mut(root_module).unwrap().edition = Edition::E2024_MIGRATION;
        let (files, res) = self.run::<PASS_COMPILATION>()?;
        if let Err((pass, mut diags)) = res {
            if pass < PASS_CFGIR {
                // errors occurred that prevented migration, remove any migration diagnostics
                // Only report blocking errors since those are stopping migration
                diags.retain(|d| {
                    !d.is_migration() && d.info().severity() >= Severity::NonblockingError
                });
                return Ok((files, Err(diags)));
            }
            let migration = generate_migration_diff(&files, &diags);
            Ok((files, Ok(migration)))
        } else {
            Ok((files, Ok(None)))
        }
    }

    pub fn check(self) -> anyhow::Result<(FilesSourceText, Result<(), Diagnostics>)> {
        let (files, res) = self.run::<PASS_COMPILATION>()?;
        Ok((files, res.map(|_| ()).map_err(|(_pass, diags)| diags)))
    }

    pub fn check_and_report(self) -> anyhow::Result<FilesSourceText> {
        let (files, res) = self.check()?;
        unwrap_or_report_diagnostics(&files, res);
        Ok(files)
    }

    pub fn build(
        self,
    ) -> anyhow::Result<(
        FilesSourceText,
        Result<(Vec<AnnotatedCompiledUnit>, Diagnostics), Diagnostics>,
    )> {
        let (files, res) = self.run::<PASS_COMPILATION>()?;
        Ok((
            files,
            res.map(|(_comments, stepped)| stepped.into_compiled_units())
                .map_err(|(_pass, diags)| diags),
        ))
    }

    pub fn build_and_report(self) -> anyhow::Result<(FilesSourceText, Vec<AnnotatedCompiledUnit>)> {
        let (files, units_res) = self.build()?;
        let (units, warnings) = unwrap_or_report_diagnostics(&files, units_res);
        report_warnings(&files, warnings);
        Ok((files, units))
    }
}

impl<'a, const P: Pass> SteppedCompiler<'a, P> {
    fn run_impl<const TARGET: Pass>(
        self,
    ) -> Result<SteppedCompiler<'a, TARGET>, (Pass, Diagnostics)> {
        assert!(P > EMPTY_COMPILER);
        assert!(self.program.is_some());
        assert!(self.program.as_ref().unwrap().equivalent_pass() == P);
        assert!(
            P <= PASS_COMPILATION,
            "Invalid pass for run_to. Initial pass is too large."
        );
        assert!(
            P <= TARGET,
            "Invalid pass for run_to. Target pass precedes the current pass"
        );
        let Self {
            mut compilation_env,
            pre_compiled_lib,
            program,
        } = self;
        let new_prog = run(
            &mut compilation_env,
            pre_compiled_lib,
            program.unwrap(),
            TARGET,
            |_, _| (),
        )?;
        assert!(new_prog.equivalent_pass() == TARGET);
        Ok(SteppedCompiler {
            compilation_env,
            pre_compiled_lib,
            program: Some(new_prog),
        })
    }

    pub fn compilation_env(&mut self) -> &mut CompilationEnv {
        &mut self.compilation_env
    }
}

macro_rules! ast_stepped_compilers {
    ($(($pass:ident, $mod:ident, $result:ident, $at_ast:ident, $new:ident)),*) => {
        impl<'a> SteppedCompiler<'a, EMPTY_COMPILER> {
            $(
                pub fn $at_ast(self, ast: $mod::ast::Program) -> SteppedCompiler<'a, {$pass}> {
                    let Self {
                        compilation_env,
                        pre_compiled_lib,
                        program,
                    } = self;
                    assert!(program.is_none());
                    SteppedCompiler::$new(
                        compilation_env,
                        pre_compiled_lib,
                        ast
                    )
                }
            )*
        }

        $(
            impl<'a> SteppedCompiler<'a, {$pass}> {
                fn $new(
                    compilation_env: CompilationEnv,
                    pre_compiled_lib: Option<&'a FullyCompiledProgram>,
                    ast: $mod::ast::Program,
                ) -> Self {
                    Self {
                        compilation_env,
                        pre_compiled_lib,
                        program: Some(PassResult::$result(ast)),
                    }
                }

                pub fn run<const TARGET: Pass>(
                    self,
                ) -> Result<SteppedCompiler<'a, TARGET>, (Pass, Diagnostics)> {
                    self.run_impl()
                }

                pub fn into_ast(self) -> (SteppedCompiler<'a, EMPTY_COMPILER>, $mod::ast::Program) {
                    let Self {
                        compilation_env,
                        pre_compiled_lib,
                        program,
                    } = self;
                    let ast = match program {
                        Some(PassResult::$result(ast)) => ast,
                        _ => panic!(),
                    };
                    let next = SteppedCompiler {
                        compilation_env,
                        pre_compiled_lib,
                        program: None,
                    };
                    (next, ast)
                }

                pub fn check(self) -> Result<(), (Pass, Diagnostics)> {
                    self.run::<PASS_COMPILATION>()?;
                    Ok(())
                }

                pub fn build(
                    self,
                ) -> Result<(Vec<AnnotatedCompiledUnit>, Diagnostics), (Pass, Diagnostics)> {
                    let units = self.run::<PASS_COMPILATION>()?.into_compiled_units();
                    Ok(units)
                }

                pub fn check_and_report(self, files: &FilesSourceText)  {
                    let errors_result = self.check().map_err(|(_, diags)| diags);
                    unwrap_or_report_diagnostics(&files, errors_result);
                }

                pub fn build_and_report(
                    self,
                    files: &FilesSourceText,
                ) -> Vec<AnnotatedCompiledUnit> {
                    let units_result = self.build().map_err(|(_, diags)| diags);
                    let (units, warnings) = unwrap_or_report_diagnostics(&files, units_result);
                    report_warnings(&files, warnings);
                    units
                }
            }
        )*
    };
}

ast_stepped_compilers!(
    (PASS_PARSER, parser, Parser, at_parser, new_at_parser),
    (
        PASS_EXPANSION,
        expansion,
        Expansion,
        at_expansion,
        new_at_expansion
    ),
    (PASS_NAMING, naming, Naming, at_naming, new_at_naming),
    (PASS_TYPING, typing, Typing, at_typing, new_at_typing),
    (PASS_HLIR, hlir, HLIR, at_hlir, new_at_hlir),
    (PASS_CFGIR, cfgir, CFGIR, at_cfgir, new_at_cfgir)
);

impl<'a> SteppedCompiler<'a, PASS_COMPILATION> {
    pub fn into_compiled_units(self) -> (Vec<AnnotatedCompiledUnit>, Diagnostics) {
        let Self {
            compilation_env: _,
            pre_compiled_lib: _,
            program,
        } = self;
        match program {
            Some(PassResult::Compilation(units, warnings)) => (units, warnings),
            _ => panic!(),
        }
    }
}

/// Given a set of dependencies, precompile them and save the ASTs so that they can be used again
/// to compile against without having to recompile these dependencies
pub fn construct_pre_compiled_lib<Paths: Into<Symbol>, NamedAddress: Into<Symbol>>(
    targets: Vec<PackagePaths<Paths, NamedAddress>>,
    interface_files_dir_opt: Option<String>,
    flags: Flags,
) -> anyhow::Result<Result<FullyCompiledProgram, (FilesSourceText, Diagnostics)>> {
    let (files, pprog_and_comments_res) =
        Compiler::from_package_paths(targets, Vec::<PackagePaths<Paths, NamedAddress>>::new())?
            .set_interface_files_dir_opt(interface_files_dir_opt)
            .set_flags(flags)
            .run::<PASS_PARSER>()?;

    let (_comments, stepped) = match pprog_and_comments_res {
        Err((_pass, errors)) => return Ok(Err((files, errors))),
        Ok(res) => res,
    };

    let (empty_compiler, ast) = stepped.into_ast();
    let mut compilation_env = empty_compiler.compilation_env;
    let start = PassResult::Parser(ast);
    let mut parser = None;
    let mut expansion = None;
    let mut naming = None;
    let mut typing = None;
    let mut hlir = None;
    let mut cfgir = None;
    let mut compiled = None;

    let save_result = |cur: &PassResult, _env: &CompilationEnv| match cur {
        PassResult::Parser(prog) => {
            assert!(parser.is_none());
            parser = Some(prog.clone())
        }
        PassResult::Expansion(eprog) => {
            assert!(expansion.is_none());
            expansion = Some(eprog.clone())
        }
        PassResult::Naming(nprog) => {
            assert!(naming.is_none());
            naming = Some(nprog.clone())
        }
        PassResult::Typing(tprog) => {
            assert!(typing.is_none());
            typing = Some(tprog.clone())
        }
        PassResult::HLIR(hprog) => {
            assert!(hlir.is_none());
            hlir = Some(hprog.clone());
        }
        PassResult::CFGIR(cprog) => {
            assert!(cfgir.is_none());
            cfgir = Some(cprog.clone());
        }
        PassResult::Compilation(units, _final_diags) => {
            assert!(compiled.is_none());
            compiled = Some(units.clone())
        }
    };
    match run(
        &mut compilation_env,
        None,
        start,
        PASS_COMPILATION,
        save_result,
    ) {
        Err((_pass, errors)) => Ok(Err((files, errors))),
        Ok(_) => Ok(Ok(FullyCompiledProgram {
            files,
            parser: parser.unwrap(),
            expansion: expansion.unwrap(),
            naming: naming.unwrap(),
            typing: typing.unwrap(),
            hlir: hlir.unwrap(),
            cfgir: cfgir.unwrap(),
            compiled: compiled.unwrap(),
        })),
    }
}

//**************************************************************************************************
// Utils
//**************************************************************************************************

macro_rules! dir_path {
    ($($dir:expr),+) => {{
        let mut p = PathBuf::new();
        $(p.push($dir);)+
        p
    }};
}

macro_rules! file_path {
    ($dir:expr, $name:expr, $ext:expr) => {{
        let mut p = PathBuf::from($dir);
        p.push($name);
        p.set_extension($ext);
        p
    }};
}

/// Runs the bytecode verifier on the compiled units
/// Fails if the bytecode verifier errors
pub fn sanity_check_compiled_units(
    files: FilesSourceText,
    compiled_units: &[AnnotatedCompiledUnit],
) {
    let ice_errors = compiled_unit::verify_units(compiled_units);
    if !ice_errors.is_empty() {
        report_diagnostics(&files, ice_errors)
    }
}

/// Given a file map and a set of compiled programs, saves the compiled programs to disk
pub fn output_compiled_units(
    bytecode_version: Option<u32>,
    emit_source_maps: bool,
    files: FilesSourceText,
    compiled_units: Vec<AnnotatedCompiledUnit>,
    out_dir: &str,
) -> anyhow::Result<()> {
    const MODULE_SUB_DIR: &str = "modules";
    fn num_digits(n: usize) -> usize {
        format!("{}", n).len()
    }
    fn format_idx(idx: usize, width: usize) -> String {
        format!("{:0width$}", idx, width = width)
    }

    macro_rules! emit_unit {
        ($path:ident, $unit:ident) => {{
            if emit_source_maps {
                $path.set_extension(SOURCE_MAP_EXTENSION);
                fs::write($path.as_path(), &$unit.serialize_source_map())?;
            }

            $path.set_extension(MOVE_COMPILED_EXTENSION);
            fs::write($path.as_path(), &$unit.serialize(bytecode_version))?
        }};
    }

    let ice_errors = compiled_unit::verify_units(&compiled_units);

    // modules
    if !compiled_units.is_empty() {
        std::fs::create_dir_all(dir_path!(out_dir, MODULE_SUB_DIR))?;
    }
    let digit_width = num_digits(compiled_units.len());
    for (idx, unit) in compiled_units.into_iter().enumerate() {
        let unit = unit.into_compiled_unit();
        let mut path = dir_path!(
            out_dir,
            MODULE_SUB_DIR,
            format!("{}_{}", format_idx(idx, digit_width), unit.name())
        );
        emit_unit!(path, unit);
    }

    if !ice_errors.is_empty() {
        report_diagnostics(&files, ice_errors)
    }
    Ok(())
}

fn generate_interface_files_for_deps(
    deps: &mut Vec<IndexedVfsPackagePath>,
    interface_files_dir_opt: Option<String>,
    module_to_named_address: &BTreeMap<CompiledModuleId, String>,
) -> anyhow::Result<()> {
    let interface_files_paths =
        generate_interface_files(deps, interface_files_dir_opt, module_to_named_address, true)?;
    deps.extend(interface_files_paths);
    // Remove bytecode files
    deps.retain(|p| !p.path.as_str().ends_with(MOVE_COMPILED_EXTENSION));
    Ok(())
}

pub fn generate_interface_files(
    mv_file_locations: &mut [IndexedVfsPackagePath],
    interface_files_dir_opt: Option<String>,
    module_to_named_address: &BTreeMap<CompiledModuleId, String>,
    separate_by_hash: bool,
) -> anyhow::Result<Vec<IndexedVfsPackagePath>> {
    let mv_files = {
        let mut v = vec![];
        let (mv_magic_files, other_file_locations): (Vec<_>, Vec<_>) =
            mv_file_locations.iter().cloned().partition(|s| {
                let is_file = s
                    .path
                    .metadata()
                    .map(|d| d.file_type == VfsFileType::File)
                    .unwrap_or(false);
                is_file && has_compiled_module_magic_number(&s.path)
            });
        v.extend(mv_magic_files);
        for IndexedVfsPackagePath {
            package,
            path,
            named_address_map,
        } in other_file_locations
        {
            v.extend(
                find_filenames_vfs(&[path], |path| {
                    path.extension()
                        .map(|e| e.as_str() == MOVE_COMPILED_EXTENSION)
                        .unwrap_or(false)
                })?
                .into_iter()
                .map(|path| IndexedVfsPackagePath {
                    package,
                    path,
                    named_address_map,
                }),
            );
        }
        v
    };
    if mv_files.is_empty() {
        return Ok(vec![]);
    }

    let interface_files_dir =
        interface_files_dir_opt.unwrap_or_else(|| DEFAULT_OUTPUT_DIR.to_string());
    let interface_sub_dir = dir_path!(interface_files_dir, MOVE_COMPILED_INTERFACES_DIR);
    let all_addr_dir = if separate_by_hash {
        use std::{
            collections::hash_map::DefaultHasher,
            hash::{Hash, Hasher},
        };
        const HASH_DELIM: &str = "%|%";

        let mut hasher = DefaultHasher::new();
        mv_files.len().hash(&mut hasher);
        HASH_DELIM.hash(&mut hasher);
        for IndexedVfsPackagePath { path, .. } in &mv_files {
            let mut buf = vec![];
            path.open_file()?.read_to_end(&mut buf)?;
            buf.hash(&mut hasher);
            HASH_DELIM.hash(&mut hasher);
        }

        let mut dir = interface_sub_dir;
        dir.push(format!("{:020}", hasher.finish()));
        dir
    } else {
        interface_sub_dir
    };

    // interface files for dependencies are generated into a separate in-memory virtual file
    // system (`deps_out_vfs`) and subsequently read by the parser (input for interface
    // generation is still read from the "regular" virtual file system, that is `vfs`)
    let deps_out_vfs = VfsPath::new(MemoryFS::new());
    let mut result = vec![];
    for IndexedVfsPackagePath {
        package,
        path,
        named_address_map,
    } in mv_files
    {
        let (id, interface_contents) =
            interface_generator::write_file_to_string(module_to_named_address, &path)?;
        let addr_dir = dir_path!(all_addr_dir.clone(), format!("{}", id.address()));
        let file_path = Symbol::from(
            file_path!(addr_dir.clone(), format!("{}", id.name()), MOVE_EXTENSION)
                .to_string_lossy()
                .to_string(),
        );
        let vfs_path = deps_out_vfs.join(file_path)?;
        vfs_path.parent().create_dir_all()?;
        vfs_path
            .create_file()?
            .write_all(interface_contents.as_bytes())?;

        result.push(IndexedVfsPackagePath {
            package,
            path: vfs_path,
            named_address_map,
        });
    }

    Ok(result)
}

fn has_compiled_module_magic_number(path: &VfsPath) -> bool {
    use move_binary_format::file_format_common::BinaryConstants;
    let mut file = match path.open_file() {
        Err(_) => return false,
        Ok(f) => f,
    };
    let mut magic = [0u8; BinaryConstants::MOVE_MAGIC_SIZE];
    let num_bytes_read = match file.read(&mut magic) {
        Err(_) => return false,
        Ok(n) => n,
    };
    num_bytes_read == BinaryConstants::MOVE_MAGIC_SIZE && magic == BinaryConstants::MOVE_MAGIC
}

pub fn move_check_for_errors(
    comments_and_compiler_res: Result<
        (CommentMap, SteppedCompiler<'_, PASS_PARSER>),
        (Pass, Diagnostics),
    >,
) -> Diagnostics {
    fn try_impl(
        comments_and_compiler_res: Result<
            (CommentMap, SteppedCompiler<'_, PASS_PARSER>),
            (Pass, Diagnostics),
        >,
    ) -> Result<(Vec<AnnotatedCompiledUnit>, Diagnostics), (Pass, Diagnostics)> {
        let (_, compiler) = comments_and_compiler_res?;

        let (mut compiler, cfgir) = compiler.run::<PASS_CFGIR>()?.into_ast();
        let compilation_env = compiler.compilation_env();
        if compilation_env.flags().is_testing() {
            unit_test::plan_builder::construct_test_plan(compilation_env, None, &cfgir);
        }

        let (units, diags) = compiler.at_cfgir(cfgir).build()?;
        Ok((units, diags))
    }

    let (units, inner_diags) = match try_impl(comments_and_compiler_res) {
        Ok((units, inner_diags)) => (units, inner_diags),
        Err((_pass, inner_diags)) => return inner_diags,
    };
    let mut diags = compiled_unit::verify_units(&units);
    diags.extend(inner_diags);
    diags
}

//**************************************************************************************************
// Translations
//**************************************************************************************************

impl PassResult {
    pub fn equivalent_pass(&self) -> Pass {
        match self {
            PassResult::Parser(_) => PASS_PARSER,
            PassResult::Expansion(_) => PASS_EXPANSION,
            PassResult::Naming(_) => PASS_NAMING,
            PassResult::Typing(_) => PASS_TYPING,
            PassResult::HLIR(_) => PASS_HLIR,
            PassResult::CFGIR(_) => PASS_CFGIR,
            PassResult::Compilation(_, _) => PASS_COMPILATION,
        }
    }
}

fn run(
    compilation_env: &mut CompilationEnv,
    pre_compiled_lib: Option<&FullyCompiledProgram>,
    cur: PassResult,
    until: Pass,
    result_check: impl FnMut(&PassResult, &CompilationEnv),
) -> Result<PassResult, (Pass, Diagnostics)> {
    #[growing_stack]
    fn rec(
        compilation_env: &mut CompilationEnv,
        pre_compiled_lib: Option<&FullyCompiledProgram>,
        cur: PassResult,
        until: Pass,
        mut result_check: impl FnMut(&PassResult, &CompilationEnv),
    ) -> Result<PassResult, (Pass, Diagnostics)> {
        let cur_pass = cur.equivalent_pass();
        compilation_env
            .check_diags_at_or_above_severity(Severity::Bug)
            .map_err(|diags| (cur_pass, diags))?;
        assert!(
            until <= PASS_COMPILATION,
            "Invalid pass for run_to. Target is greater than maximum pass"
        );
        result_check(&cur, compilation_env);
        if cur.equivalent_pass() >= until {
            return Ok(cur);
        }

        match cur {
            PassResult::Parser(prog) => {
                let eprog = {
                    let prog = unit_test::filter_test_members::program(compilation_env, prog);
                    let prog = verification_attribute_filter::program(compilation_env, prog);
                    expansion::translate::program(compilation_env, pre_compiled_lib, prog)
                };
                rec(
                    compilation_env,
                    pre_compiled_lib,
                    PassResult::Expansion(eprog),
                    until,
                    result_check,
                )
            }
            PassResult::Expansion(eprog) => {
                let nprog = naming::translate::program(compilation_env, pre_compiled_lib, eprog);
                rec(
                    compilation_env,
                    pre_compiled_lib,
                    PassResult::Naming(nprog),
                    until,
                    result_check,
                )
            }
            PassResult::Naming(nprog) => {
                let tprog = typing::translate::program(compilation_env, pre_compiled_lib, nprog);
                rec(
                    compilation_env,
                    pre_compiled_lib,
                    PassResult::Typing(tprog),
                    until,
                    result_check,
                )
            }
            PassResult::Typing(tprog) => {
                compilation_env
                    .check_diags_at_or_above_severity(Severity::BlockingError)
                    .map_err(|diags| (cur_pass, diags))?;
                let hprog = hlir::translate::program(compilation_env, pre_compiled_lib, tprog);
                rec(
                    compilation_env,
                    pre_compiled_lib,
                    PassResult::HLIR(hprog),
                    until,
                    result_check,
                )
            }
            PassResult::HLIR(hprog) => {
                let cprog = cfgir::translate::program(compilation_env, pre_compiled_lib, hprog);
                rec(
                    compilation_env,
                    pre_compiled_lib,
                    PassResult::CFGIR(cprog),
                    until,
                    result_check,
                )
            }
            PassResult::CFGIR(cprog) => {
                // Don't generate bytecode if there are any errors
                compilation_env
                    .check_diags_at_or_above_severity(Severity::NonblockingError)
                    .map_err(|diags| (cur_pass, diags))?;
                let compiled_units =
                    to_bytecode::translate::program(compilation_env, pre_compiled_lib, cprog);
                // Report any errors from bytecode generation
                compilation_env
                    .check_diags_at_or_above_severity(Severity::NonblockingError)
                    .map_err(|diags| (PASS_COMPILATION, diags))?;
                let warnings = compilation_env.take_final_warning_diags();
                assert!(until == PASS_COMPILATION);
                rec(
                    compilation_env,
                    pre_compiled_lib,
                    PassResult::Compilation(compiled_units, warnings),
                    PASS_COMPILATION,
                    result_check,
                )
            }
            PassResult::Compilation(_, _) => unreachable!("ICE Pass::Compilation is >= all passes"),
        }
    }
    rec(compilation_env, pre_compiled_lib, cur, until, result_check)
}

//**************************************************************************************************
// traits
//**************************************************************************************************

impl From<AbsIntVisitorObj> for Visitor {
    fn from(f: AbsIntVisitorObj) -> Self {
        Self::AbsIntVisitor(f)
    }
}
