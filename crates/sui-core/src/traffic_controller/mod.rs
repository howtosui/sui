// Copyright (c) 2021, Facebook, Inc. and its affiliates
// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

pub mod nodefw_client;
#[cfg(debug_assertions)]
pub mod nodefw_test_server;

use std::net::{IpAddr, SocketAddr};
use std::{collections::HashMap, sync::Arc};

use crate::traffic_controller::nodefw_client::{BlockAddress, BlockAddresses, NodeFWClient};
use chrono::{DateTime, Utc};
use jsonrpsee::types::error::ErrorCode;
use mysten_metrics::spawn_monitored_task;
use parking_lot::RwLock;
use sui_types::error::SuiError;
use sui_types::traffic_control::{
    Policy, PolicyConfig, PolicyResponse, RemoteFirewallConfig, ServiceResponse,
    TrafficControlPolicy, TrafficTally,
};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tracing::{info, warn};

type BlocklistT = Arc<RwLock<HashMap<IpAddr, DateTime<Utc>>>>;

#[derive(Clone, Debug)]
struct Blocklists {
    connection_ips: BlocklistT,
    proxy_ips: BlocklistT,
}

#[derive(Clone, Debug)]
pub struct TrafficController {
    tally_channel: mpsc::Sender<TrafficTally>,
    blocklists: Blocklists,
    //metrics: TrafficControllerMetrics, // TODO
}

impl TrafficController {
    pub async fn spawn(fw_config: RemoteFirewallConfig, policy_config: PolicyConfig) -> Self {
        let (tx, rx) = mpsc::channel(policy_config.channel_capacity);
        let ret = Self {
            tally_channel: tx,
            blocklists: Blocklists {
                connection_ips: Arc::new(RwLock::new(HashMap::new())),
                proxy_ips: Arc::new(RwLock::new(HashMap::new())),
            },
        };
        let blocklists = ret.blocklists.clone();
        spawn_monitored_task!(run_tally_loop(rx, policy_config, fw_config, blocklists));
        ret
    }

    pub fn tally(&self, tally: TrafficTally) {
        // Use try_send rather than send mainly to avoid creating backpressure
        // on the caller if the channel is full, which may slow down the critical
        // path. Dropping the tally on the floor should be ok, as in this case
        // we are effectively sampling traffic, which we would need to do anyway
        // if we are overloaded
        match self.tally_channel.try_send(tally) {
            Err(TrySendError::Full(_)) => {
                warn!("TrafficController tally channel full, dropping tally");
                // TODO: metric
            }
            Err(TrySendError::Closed(_)) => {
                panic!("TrafficController tally channel closed unexpectedly");
            }
            Ok(_) => {}
        }
    }

    /// Returns true if the connection is allowed, false if it is blocked
    pub async fn check(
        &self,
        connection_ip: Option<SocketAddr>,
        proxy_ip: Option<SocketAddr>,
    ) -> bool {
        match (connection_ip, proxy_ip) {
            (Some(connection_ip), _) => self.check_and_clear_blocklist(connection_ip, true).await,
            (_, Some(proxy_ip)) => self.check_and_clear_blocklist(proxy_ip, false).await,
            _ => true,
        }
    }

    async fn check_and_clear_blocklist(&self, addr: SocketAddr, connection_ips: bool) -> bool {
        let ip = addr.ip();
        let blocklist = if connection_ips {
            self.blocklists.connection_ips.clone()
        } else {
            self.blocklists.proxy_ips.clone()
        };

        let now = Utc::now();
        let expiration = blocklist.read().get(&ip).copied();
        match expiration {
            Some(expiration) if now >= expiration => {
                {
                    info!(
                        "TESTING -- check_and_clear - clearing IP {:?} from blocklist. now: {:?}, expiration: {:?}. Blocklist before: {:?}", 
                        ip, now, expiration, blocklist.read()
                    );
                }
                {
                    blocklist.write().remove(&ip);
                }
                {
                    info!(
                        "TESTING -- check_and_clear - Blocklist after: {:?}",
                        blocklist.read(),
                    );
                }
                true
            }
            None => {
                info!("TESTING -- check_and_clear - IP {:?} not in blocklist", ip);
                true
            }
            _ => {
                info!(
                    "TESTING -- check_and_clear - ip {:?} in blocklist, now: {:?}, expiration: {:?}, blocklist: {:?}",
                    ip, now, expiration, blocklist.read()
                );
                false
            }
        }
    }
}

// TODO: Needs thorough testing/auditing before this can be used in error policy
//
/// Errors that are tallied and can be used to determine if a request should be blocked.
fn is_tallyable_error(response: &ServiceResponse) -> bool {
    match response {
        ServiceResponse::Validator(Err(err)) => {
            matches!(
                err,
                SuiError::UserInputError { .. }
                    | SuiError::InvalidSignature { .. }
                    | SuiError::SignerSignatureAbsent { .. }
                    | SuiError::SignerSignatureNumberMismatch { .. }
                    | SuiError::IncorrectSigner { .. }
                    | SuiError::UnknownSigner { .. }
                    | SuiError::WrongEpoch { .. }
            )
        }
        ServiceResponse::Fullnode(resp) => {
            matches!(
                resp.error_code.map(ErrorCode::from),
                Some(ErrorCode::InvalidRequest) | Some(ErrorCode::InvalidParams)
            )
        }

        _ => false,
    }
}

async fn run_tally_loop(
    mut receiver: mpsc::Receiver<TrafficTally>,
    policy_config: PolicyConfig,
    fw_config: RemoteFirewallConfig,
    blocklists: Blocklists,
) {
    let mut spam_policy = policy_config.clone().to_spam_policy();
    let mut error_policy = policy_config.clone().to_error_policy();
    let spam_blocklists = Arc::new(blocklists.clone());
    let error_blocklists = Arc::new(blocklists);
    let node_fw_client = if !(fw_config.delegate_spam_blocking || fw_config.delegate_error_blocking)
    {
        None
    } else {
        Some(NodeFWClient::new(fw_config.remote_fw_url.clone()))
    };

    loop {
        tokio::select! {
            received = receiver.recv() => match received {
                Some(tally) => {
                    if let Err(err) = handle_spam_tally(
                        &mut spam_policy,
                        &policy_config,
                        &node_fw_client,
                        &fw_config,
                        tally.clone(),
                        spam_blocklists.clone(),
                    )
                    .await {
                        warn!("Error handling spam tally: {}", err);
                    }

                    if let Err(err) = handle_error_tally(
                        &mut error_policy,
                        &policy_config,
                        &node_fw_client,
                        &fw_config,
                        tally,
                        error_blocklists.clone(),
                    )
                    .await {
                        warn!("Error handling error tally: {}", err);
                    }
                }
                None => {
                    panic!("TrafficController tally channel closed unexpectedly");
                },
            }
        }
    }
}

async fn handle_error_tally(
    policy: &mut TrafficControlPolicy,
    policy_config: &PolicyConfig,
    nodefw_client: &Option<NodeFWClient>,
    fw_config: &RemoteFirewallConfig,
    tally: TrafficTally,
    blocklists: Arc<Blocklists>,
) -> Result<(), reqwest::Error> {
    if tally.result.is_ok() {
        return Ok(());
    }
    if !is_tallyable_error(&tally.result) {
        return Ok(());
    }
    let resp = policy.handle_tally(tally.clone());
    if fw_config.delegate_error_blocking {
        let client = nodefw_client
            .as_ref()
            .expect("Expected NodeFWClient for blocklist delegation");
        delegate_policy_response(
            resp,
            policy_config,
            client,
            tally,
            fw_config.destination_port,
        )
        .await
    } else {
        handle_policy_response(resp, policy_config, tally, blocklists).await;
        Ok(())
    }
}

async fn handle_spam_tally(
    policy: &mut TrafficControlPolicy,
    policy_config: &PolicyConfig,
    nodefw_client: &Option<NodeFWClient>,
    fw_config: &RemoteFirewallConfig,
    tally: TrafficTally,
    blocklists: Arc<Blocklists>,
) -> Result<(), reqwest::Error> {
    let resp = policy.handle_tally(tally.clone());
    if fw_config.delegate_spam_blocking {
        let client = nodefw_client
            .as_ref()
            .expect("Expected NodeFWClient for blocklist delegation");
        delegate_policy_response(
            resp,
            policy_config,
            client,
            tally,
            fw_config.destination_port,
        )
        .await
    } else {
        handle_policy_response(resp, policy_config, tally, blocklists.clone()).await;
        Ok(())
    }
}

async fn handle_policy_response(
    PolicyResponse {
        block_connection_ip,
        block_proxy_ip,
    }: PolicyResponse,
    PolicyConfig {
        connection_blocklist_ttl_sec,
        proxy_blocklist_ttl_sec,
        ..
    }: &PolicyConfig,
    tally: TrafficTally,
    blocklists: Arc<Blocklists>,
) {
    if block_connection_ip {
        info!("Blocking connection IP: {:?}", tally.connection_ip);
        blocklists.connection_ips.write().insert(
            tally
                .connection_ip
                .expect("Expected connection IP if policy is blocking it"),
            Utc::now() + chrono::Duration::seconds(*connection_blocklist_ttl_sec as i64),
        );
    }
    if block_proxy_ip {
        info!("Blocking proxy IP: {:?}", tally.proxy_ip);
        blocklists.proxy_ips.write().insert(
            tally
                .proxy_ip
                .expect("Expected proxy IP if policy is blocking it"),
            Utc::now() + chrono::Duration::seconds(*proxy_blocklist_ttl_sec as i64),
        );
    }
}

async fn delegate_policy_response(
    PolicyResponse {
        block_connection_ip,
        block_proxy_ip,
    }: PolicyResponse,
    PolicyConfig {
        connection_blocklist_ttl_sec,
        proxy_blocklist_ttl_sec,
        ..
    }: &PolicyConfig,
    node_fw_client: &NodeFWClient,
    tally: TrafficTally,
    destination_port: u16,
) -> Result<(), reqwest::Error> {
    let mut addresses = vec![];
    if block_connection_ip {
        info!("Delegating block connection IP: {:?}", tally.connection_ip);
        addresses.push(BlockAddress {
            source_address: tally.connection_ip.unwrap().to_string(),
            destination_port,
            ttl: *connection_blocklist_ttl_sec,
        });
    }
    if block_proxy_ip {
        info!("Delegating block proxy IP: {:?}", tally.proxy_ip);
        addresses.push(BlockAddress {
            source_address: tally.proxy_ip.unwrap().to_string(),
            destination_port,
            ttl: *proxy_blocklist_ttl_sec,
        });
    }
    if addresses.is_empty() {
        Ok(())
    } else {
        node_fw_client
            .block_addresses(BlockAddresses { addresses })
            .await
    }
}
