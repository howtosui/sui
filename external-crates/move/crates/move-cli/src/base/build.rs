// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use super::reroot_path;
use clap::*;
use move_package::{BuildConfig, NEEDS_MIGRATION};
use std::path::PathBuf;

/// Build the package at `path`. If no path is provided defaults to current directory.
#[derive(Parser)]
#[clap(name = "build")]
pub struct Build;

impl Build {
    pub fn execute(self, path: Option<PathBuf>, config: BuildConfig) -> anyhow::Result<()> {
        let rerooted_path = reroot_path(path)?;
        if config.build_info.fetch_deps_only {
            let mut config = config;
            if config.build_info.test_mode {
                config.build_info.dev_mode = true;
            }
            config.download_deps_for_package(&rerooted_path, &mut std::io::stdout())?;
            return Ok(());
        }

        let result = config
            .clone()
            .cli_compile_package(&rerooted_path, &mut std::io::stdout());
        if let Err(err) = &result {
            let err_msg = err.downcast_ref::<&str>();
            if let Some(str) = err_msg {
                if matches!(str, &NEEDS_MIGRATION) {
                    let migrate_config = config.clone();
                    migrate_config.migrate_package(
                        &rerooted_path,
                        &mut std::io::stdout(),
                        &mut std::io::stdin().lock(),
                    )?;
                    self.execute_with_path(rerooted_path, config)?
                }
            }
        }
        result?;
        Ok(())
    }

    fn execute_with_path(self, path: PathBuf, config: BuildConfig) -> anyhow::Result<()> {
        config.compile_package(&path, &mut std::io::stdout())?;
        Ok(())
    }
}
