use async_trait::async_trait;
use std::fmt::Debug;
use tokio::sync::mpsc;

use super::types::*;

#[async_trait]
pub trait Agent<M: Debug + Message> {
    fn new(
        id: UniqueId,
        in_channel: mpsc::Receiver<NetworkMessage>,
        out_channel: mpsc::Sender<NetworkMessage>,
        network_config: GlobalConfig,
    ) -> Self;

    async fn run(&mut self);
}