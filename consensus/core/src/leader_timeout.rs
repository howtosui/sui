// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use crate::block::GENESIS_ROUND;
use crate::context::Context;
use crate::core::{CoreSignalsReceivers, QuorumUpdate, DEFAULT_NUM_LEADERS_PER_ROUND};
use crate::core_thread::CoreThreadDispatcher;
use std::cmp::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot::{Receiver, Sender};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{sleep_until, Instant};
use tracing::{debug, warn};

/// The leader timeout weights used to update the remaining timeout according to each leader weight.
/// Each position on the array represents the weight of the leader of a round according to their ordered position.
/// For example, on an array with values [50, 30, 20], it means that:
/// * the first leader of the round has weight 50
/// * the second leader of the round has weight 30
/// * the third leader of the round has weight 20
///
/// The weights basically dictate by what fraction the total leader timeout should be reduced when a leader
/// is found for the round. For the reduction to happen each time it is important for the leader of the previous
/// position to have been found first. The rational is to reduce the total waiting time to timeout/propose every time
/// that we have successfully received a leader in order.
#[allow(unused)]
pub(crate) const DEFAULT_LEADER_TIMEOUT_WEIGHTS: [u32; DEFAULT_NUM_LEADERS_PER_ROUND] = [100];

pub(crate) struct LeaderTimeoutTaskHandle {
    handle: JoinHandle<()>,
    stop: Sender<()>,
}

impl LeaderTimeoutTaskHandle {
    pub async fn stop(self) {
        self.stop.send(()).ok();
        self.handle.await.ok();
    }
}

pub(crate) struct LeaderTimeoutTask<
    D: CoreThreadDispatcher,
    const NUM_OF_LEADERS: usize = DEFAULT_NUM_LEADERS_PER_ROUND,
> {
    dispatcher: Arc<D>,
    quorum_update_receiver: watch::Receiver<QuorumUpdate>,
    stop: Receiver<()>,
    leader_timeout: Duration,
    leader_timeout_weights: [u32; NUM_OF_LEADERS],
}

impl<D: CoreThreadDispatcher, const NUM_OF_LEADERS: usize> LeaderTimeoutTask<D, NUM_OF_LEADERS> {
    pub fn start(
        dispatcher: Arc<D>,
        signals_receivers: &CoreSignalsReceivers,
        context: Arc<Context>,
        leader_timeout_weights: [u32; NUM_OF_LEADERS],
    ) -> LeaderTimeoutTaskHandle {
        assert_timeout_weights(&leader_timeout_weights);

        let (stop_sender, stop) = tokio::sync::oneshot::channel();
        let mut me = Self {
            dispatcher,
            stop,
            quorum_update_receiver: signals_receivers.quorum_update_receiver(),
            leader_timeout: context.parameters.leader_timeout,
            leader_timeout_weights,
        };
        let handle = tokio::spawn(async move { me.run().await });

        LeaderTimeoutTaskHandle {
            handle,
            stop: stop_sender,
        }
    }

    async fn run(&mut self) {
        let _ = self.leader_timeout_weights;
        let quorum_update = &mut self.quorum_update_receiver;
        let mut last_quorum_update: QuorumUpdate = quorum_update.borrow_and_update().clone();

        let mut leader_round_timed_out = false;
        let timer_start = Instant::now();
        let leader_timeout = sleep_until(timer_start + self.leader_timeout);

        tokio::pin!(leader_timeout);

        loop {
            tokio::select! {
                // when leader timer expires then we attempt to trigger the creation of a new block.
                // If we already timed out before then the branch gets disabled, so we don't attempt
                // all the time to produce already produced blocks for that round.
                () = &mut leader_timeout, if !leader_round_timed_out => {
                    if let Err(err) = self.dispatcher.force_new_block(last_quorum_update.round.saturating_add(1)).await {
                        warn!("Error received while calling dispatcher, probably dispatcher is shutting down, will now exit: {err:?}");
                        return;
                    }
                    leader_round_timed_out = true;
                }

                // Either a new quorum round has been produced or new leaders have been accepted. Reset the leader timeout.
                Ok(_) = quorum_update.changed() => {
                    let update: QuorumUpdate = quorum_update.borrow_and_update().clone();

                    assert!(update.round > GENESIS_ROUND, "Unexpected receive of update for genesis round!");
                    assert_eq!(update.leaders.len(), NUM_OF_LEADERS, "Number of expected leaders differ from the leader timeout weight setup");

                    match update.round.cmp(&last_quorum_update.round) {
                        Ordering::Less => {
                            warn!("Received leader update for lower quorum round {} compared to previous round {}, will ignore", update.round, last_quorum_update.round);
                            continue;
                        }
                        Ordering::Equal => {
                            // Update the leader timeout
                        }
                        Ordering::Greater => {
                            //1. Now reset the timer.
                            debug!("New round has been received {}, resetting timer", update.round);
                            last_quorum_update = update;

                            leader_round_timed_out = false;

                            leader_timeout
                            .as_mut()
                            .reset(Instant::now() + self.leader_timeout);

                            //2. Update the leader timeout
                        }
                    }
                },
                _ = &mut self.stop => {
                    debug!("Stop signal has been received, now shutting down");
                    return;
                }
            }
        }
    }
}

fn assert_timeout_weights(weights: &[u32]) {
    let mut total = 0;
    for w in weights {
        total += w;
    }
    assert_eq!(total, 100, "Total weight should be 100");
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use consensus_config::Parameters;
    use parking_lot::Mutex;
    use tokio::time::{sleep, Instant};

    use crate::block::{BlockRef, Round, VerifiedBlock};
    use crate::context::Context;
    use crate::core::{CoreSignals, DEFAULT_NUM_LEADERS_PER_ROUND};
    use crate::core_thread::{CoreError, CoreThreadDispatcher};
    use crate::leader_timeout::{LeaderTimeoutTask, DEFAULT_LEADER_TIMEOUT_WEIGHTS};

    #[derive(Clone, Default)]
    struct MockCoreThreadDispatcher {
        force_new_block_calls: Arc<Mutex<Vec<(Round, Instant)>>>,
    }

    impl MockCoreThreadDispatcher {
        async fn get_force_new_block_calls(&self) -> Vec<(Round, Instant)> {
            let mut binding = self.force_new_block_calls.lock();
            let all_calls = binding.drain(0..);
            all_calls.into_iter().collect()
        }
    }

    #[async_trait]
    impl CoreThreadDispatcher for MockCoreThreadDispatcher {
        async fn add_blocks(
            &self,
            _blocks: Vec<VerifiedBlock>,
        ) -> Result<BTreeSet<BlockRef>, CoreError> {
            todo!()
        }

        async fn force_new_block(&self, round: Round) -> Result<(), CoreError> {
            self.force_new_block_calls
                .lock()
                .push((round, Instant::now()));
            Ok(())
        }

        async fn get_missing_blocks(&self) -> Result<BTreeSet<BlockRef>, CoreError> {
            todo!()
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn basic_leader_timeout() {
        let (context, _signers) = Context::new_for_test(4);
        let dispatcher = Arc::new(MockCoreThreadDispatcher::default());
        let leader_timeout = Duration::from_millis(500);
        let parameters = Parameters {
            leader_timeout,
            ..Default::default()
        };
        let context = Arc::new(context.with_parameters(parameters));
        let start = Instant::now();

        let (mut signals, signal_receivers) = CoreSignals::new();

        // spawn the task
        let _handle = LeaderTimeoutTask::start(
            dispatcher.clone(),
            &signal_receivers,
            context,
            DEFAULT_LEADER_TIMEOUT_WEIGHTS,
        );

        // send a signal that a new round has been produced.
        signals
            .quorum_update(9, vec![None; DEFAULT_NUM_LEADERS_PER_ROUND])
            .ok();

        // wait enough until a force_new_block has been received
        sleep(2 * leader_timeout).await;
        let all_calls = dispatcher.get_force_new_block_calls().await;

        assert_eq!(all_calls.len(), 1);

        let (round, timestamp) = all_calls[0];
        assert_eq!(round, 10);
        assert!(
            leader_timeout <= timestamp - start,
            "Leader timeout setting {:?} should be less than actual time difference {:?}",
            leader_timeout,
            timestamp - start
        );

        // now wait another 2 * leader_timeout, no other call should be received
        sleep(2 * leader_timeout).await;
        let all_calls = dispatcher.get_force_new_block_calls().await;

        assert_eq!(all_calls.len(), 0);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn multiple_leader_timeouts() {
        let (context, _signers) = Context::new_for_test(4);
        let dispatcher = Arc::new(MockCoreThreadDispatcher::default());
        let leader_timeout = Duration::from_millis(500);
        let parameters = Parameters {
            leader_timeout,
            ..Default::default()
        };
        let context = Arc::new(context.with_parameters(parameters));
        let now = Instant::now();

        let (mut signals, signal_receivers) = CoreSignals::new();

        // spawn the task
        let _handle = LeaderTimeoutTask::start(
            dispatcher.clone(),
            &signal_receivers,
            context,
            DEFAULT_LEADER_TIMEOUT_WEIGHTS,
        );

        // now send some signals with some small delay between them, but not enough so every round
        // manages to timeout and call the force new block method.
        signals
            .quorum_update(12, vec![None; DEFAULT_NUM_LEADERS_PER_ROUND])
            .ok();
        sleep(leader_timeout / 2).await;
        signals
            .quorum_update(13, vec![None; DEFAULT_NUM_LEADERS_PER_ROUND])
            .ok();
        sleep(leader_timeout / 2).await;
        signals
            .quorum_update(14, vec![None; DEFAULT_NUM_LEADERS_PER_ROUND])
            .ok();
        sleep(2 * leader_timeout).await;

        // only the last one should be received
        let all_calls = dispatcher.get_force_new_block_calls().await;
        let (round, timestamp) = all_calls[0];
        assert_eq!(round, 15);
        assert!(leader_timeout < timestamp - now);
    }
}
