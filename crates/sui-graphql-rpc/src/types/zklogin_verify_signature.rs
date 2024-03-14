// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::data::Db;
use crate::error::Error;
use crate::types::base64::Base64;
use crate::types::chain_identifier::ChainIdentifier;
use crate::types::dynamic_field::{DynamicField, DynamicFieldName};
use crate::types::epoch::Epoch;
use crate::types::sui_address::SuiAddress;
use crate::types::type_filter::ExactTypeFilter;
use async_graphql::*;
use fastcrypto_zkp::bn254::zk_login_api::ZkLoginEnv;
use im::hashmap::HashMap as ImHashMap;
use shared_crypto::intent::{
    AppId, Intent, IntentMessage, IntentScope, IntentVersion, PersonalMessage,
};
use sui_types::authenticator_state::{ActiveJwk, AuthenticatorStateInner};
use sui_types::crypto::ToFromBytes;
use sui_types::digests::{get_mainnet_chain_identifier, get_testnet_chain_identifier};
use sui_types::dynamic_field::{DynamicFieldType, Field};
use sui_types::signature::GenericSignature;
use sui_types::signature::{AuthenticatorTrait, VerifyParams};
use sui_types::transaction::TransactionData;
use sui_types::{TypeTag, SUI_AUTHENTICATOR_STATE_ADDRESS};
use tracing::warn;
pub async fn verify_zklogin_signature_inner(
    db: &Db,
    bytes: Base64,
    signature: Base64,
    intent_scope: u64,
    author: SuiAddress,
) -> Result<ZkLoginVerifyResult, Error> {
    // parse intent scope from u64.
    let safe_intent = if intent_scope > u8::MAX as u64 {
        return Err(Error::Client("Invalid intent scope".to_string()));
    } else {
        IntentScope::try_from(intent_scope as u8)
            .map_err(|_| Error::Client("Unsupported intent scope".to_string()))
    }?;

    // get current epoch from db.
    let Some(curr_epoch) = Epoch::query(db, None, None).await? else {
        return Err(Error::Internal(
            "Cannot get current epoch from db".to_string(),
        ));
    };
    let curr_epoch = curr_epoch.stored.epoch as u64;

    // get chain id from db and determine zklogin_env.
    let chain_id = ChainIdentifier::query(db).await?;
    let zklogin_env = match chain_id == get_mainnet_chain_identifier()
        || chain_id == get_testnet_chain_identifier()
    {
        true => ZkLoginEnv::Prod,
        _ => ZkLoginEnv::Test,
    };

    // fetch on-chain JWKs from dynamic field of system object.
    let df = DynamicField::query(
        db,
        SUI_AUTHENTICATOR_STATE_ADDRESS.into(),
        None,
        DynamicFieldName {
            type_: ExactTypeFilter(TypeTag::U64),
            bcs: Base64(bcs::to_bytes(&1u64).unwrap()),
        },
        DynamicFieldType::DynamicField,
        None,
    )
    .await
    .map_err(|e| as_jwks_read_error(e.to_string()))?;

    let binding = df.ok_or(as_jwks_read_error("Cannot find df".to_string()))?;
    let move_object = &binding.super_.native;

    let inner = bcs::from_bytes::<Field<u64, AuthenticatorStateInner>>(move_object.contents())
        .map_err(|e| as_jwks_read_error(e.to_string()))?
        .value;

    // construct verify params with active jwks and zklogin_env.

    let mut oidc_provider_jwks = ImHashMap::new();
    for active_jwk in &inner.active_jwks {
        let ActiveJwk { jwk_id, jwk, .. } = active_jwk;
        match oidc_provider_jwks.entry(jwk_id.clone()) {
            im::hashmap::Entry::Occupied(_) => {
                warn!("JWK with kid {:?} already exists", jwk_id);
            }
            im::hashmap::Entry::Vacant(entry) => {
                entry.insert(jwk.clone());
            }
        }
    }
    let verify_params = VerifyParams::new(oidc_provider_jwks, vec![], zklogin_env, true, true);

    match GenericSignature::from_bytes(&signature.0)
        .map_err(|_| Error::Client("Cannot parse generic signature".to_string()))?
    {
        GenericSignature::ZkLoginAuthenticator(zk) => {
            let bytes = bytes.0;
            match safe_intent {
                IntentScope::TransactionData => {
                    let tx_data: TransactionData = bcs::from_bytes(&bytes)
                        .map_err(|_| Error::Client("Invalid tx data bytes".to_string()))?;
                    let intent_msg = IntentMessage::new(Intent::sui_transaction(), tx_data.clone());
                    let tx_sender = tx_data.execution_parts().1;
                    if tx_sender != author.into() {
                        return Err(Error::Client("Tx sender mismatch author".to_string()));
                    }
                    match zk.verify_authenticator(
                        &intent_msg,
                        tx_sender,
                        Some(curr_epoch),
                        &verify_params,
                    ) {
                        Ok(_) => Ok(ZkLoginVerifyResult { errors: None }),
                        Err(e) => Ok(ZkLoginVerifyResult {
                            errors: Some(vec![e.to_string()]),
                        }),
                    }
                }
                IntentScope::PersonalMessage => {
                    let data = PersonalMessage { message: bytes };
                    let intent_msg = IntentMessage::new(
                        Intent {
                            scope: IntentScope::PersonalMessage,
                            version: IntentVersion::V0,
                            app_id: AppId::Sui,
                        },
                        data,
                    );

                    match zk.verify_authenticator(
                        &intent_msg,
                        author.into(),
                        Some(curr_epoch),
                        &verify_params,
                    ) {
                        Ok(_) => Ok(ZkLoginVerifyResult { errors: None }),
                        Err(e) => Ok(ZkLoginVerifyResult {
                            errors: Some(vec![e.to_string()]),
                        }),
                    }
                }
                _ => Ok(ZkLoginVerifyResult {
                    errors: Some(vec!["Invalid intent scope".to_string()]),
                }),
            }
        }
        _ => Ok(ZkLoginVerifyResult {
            errors: Some(vec!["Endpoint only supports zkLogin signature".to_string()]),
        }),
    }
}

/// Format the error message for failed JWK read.
fn as_jwks_read_error(e: String) -> Error {
    Error::Internal(format!("Failed to read JWK from system object 0x7: {}", e))
}

/// The result of the zkLogin signature verification.
#[derive(SimpleObject, Clone)]
pub(crate) struct ZkLoginVerifyResult {
    /// The errors field captures any verification error
    pub errors: Option<Vec<String>>,
}
