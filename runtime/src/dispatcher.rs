//! Runtime call dispatcher.
use std::{
    convert::TryInto,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
        mpsc as std_mpsc,
    },
    thread,
};

use lazy_static::lazy_static;
use anyhow::Result as AnyResult;
use io_context::Context;
use slog::{debug, error, info, warn, Logger};
use tokio::sync::mpsc;

use crate::{
    attestation, cache,
    common::{
        crypto::{
            hash::Hash,
            signature::{Signature, Signer},
        },
        logger::get_logger,
        process,
    },
    consensus::{
        beacon::EpochTime,
        roothash::{self, ComputeResultsHeader, Header, COMPUTE_RESULTS_HEADER_CONTEXT},
        verifier::Verifier,
        LightBlock,
    },
    enclave_rpc::{
        demux::Demux as RpcDemux,
        dispatcher::Dispatcher as RpcDispatcher,
        types::{Message as RpcMessage, Request as RpcRequest},
        Context as RpcContext,
    },
    protocol::{Protocol, ProtocolUntrustedLocalStorage},
    rak::RAK,
    storage::mkvs::{sync::NoopReadSyncer, OverlayTree, Root, RootType, Tree, FallibleMKVS},
    transaction::{
        dispatcher::{Dispatcher as TxnDispatcher, NoopDispatcher as TxnNoopDispatcher},
        tree::Tree as TxnTree,
        types::TxnBatch,
        Context as TxnContext,
        dispatcher::ExecuteBatchResult,
    },
    types::{Body, ComputedBatch, Error, ExecutionMode, TxBatchResult, CheckTxResult},
};

lazy_static! {
    static ref CHECK_TREE: Arc<Mutex<Option<Tree>>> = Arc::new(Mutex::new(None));
    static ref EXECUTE_TREE: Arc<Mutex<Option<Tree>>> = Arc::new(Mutex::new(None));
}

/// Maximum amount of requests that can be in the dispatcher queue.
const BACKLOG_SIZE: usize = 10000;

/// Interface for dispatcher initializers.
pub trait Initializer: Send + Sync {
    /// Initializes the dispatcher(s).
    fn init(&self, state: PreInitState<'_>) -> PostInitState;
}

impl<F> Initializer for F
where
    F: Fn(PreInitState<'_>) -> PostInitState + Send + Sync,
{
    fn init(&self, state: PreInitState<'_>) -> PostInitState {
        (*self)(state)
    }
}

/// State available before initialization.
pub struct PreInitState<'a> {
    /// Protocol instance.
    pub protocol: &'a Arc<Protocol>,
    /// Runtime Attestation Key instance.
    pub rak: &'a Arc<RAK>,
    /// RPC demultiplexer instance.
    pub rpc_demux: &'a mut RpcDemux,
    /// RPC dispatcher instance.
    pub rpc_dispatcher: &'a mut RpcDispatcher,
    /// Consensus verifier instance.
    pub consensus_verifier: &'a Arc<dyn Verifier>,
}

/// State returned by the initializer.
#[derive(Default)]
pub struct PostInitState {
    /// Optional transaction dispatcher that should be used.
    pub txn_dispatcher: Option<Box<dyn TxnDispatcher>>,
}

/// A guard that will abort the process if dropped while panicking.
///
/// This is to ensure that the runtime will terminate in case there is
/// a panic encountered during dispatch and the runtime is built with
/// a non-abort panic handler.
struct AbortOnPanic;

impl Drop for AbortOnPanic {
    fn drop(&mut self) {
        if thread::panicking() {
            process::abort();
        }
    }
}

impl From<tokio::task::JoinError> for Error {
    fn from(e: tokio::task::JoinError) -> Self {
        Error::new(
            "dispatcher",
            1,
            &format!("error while processing request: {}", e),
        )
    }
}

/// State related to dispatching a runtime transaction.
struct TxDispatchState {
    mode: ExecutionMode,
    consensus_block: LightBlock,
    consensus_verifier: Arc<dyn Verifier>,
    header: Header,
    epoch: EpochTime,
    round_results: roothash::RoundResults,
    max_messages: u32,
    check_only: bool,
}

/// State provided by the protocol upon successful initialization.
struct ProtocolState {
    protocol: Arc<Protocol>,
    consensus_verifier: Arc<dyn Verifier>,
}

/// State held by the dispatcher, shared between all async tasks.
#[derive(Clone)]
struct State {
    protocol: Arc<Protocol>,
    consensus_verifier: Arc<dyn Verifier>,
    dispatcher: Arc<Dispatcher>,
    rpc_demux: Arc<Mutex<RpcDemux>>,
    rpc_dispatcher: Arc<RpcDispatcher>,
    txn_dispatcher: Arc<dyn TxnDispatcher>,
    #[cfg_attr(not(target_env = "sgx"), allow(unused))]
    attestation_handler: attestation::Handler,
    cache_set: cache::CacheSet,
}

#[derive(Debug)]
enum Command {
    Request(Context, u64, Body),
    Abort(mpsc::Sender<()>),
}

/// Runtime call dispatcher.
pub struct Dispatcher {
    logger: Logger,
    queue_tx: mpsc::Sender<Command>,
    rak: Arc<RAK>,
    abort_batch: Arc<AtomicBool>,

    state: Mutex<Option<ProtocolState>>,
    state_cond: Condvar,

    tokio_runtime: tokio::runtime::Runtime,
}

impl Dispatcher {
    #[cfg(target_env = "sgx")]
    fn new_tokio_runtime() -> tokio::runtime::Runtime {
        // In an SGX environment we use a single-threaded Tokio runtime.
        tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(2) // Limited in SGX.
            .thread_keep_alive(std::time::Duration::from_secs(120))
            .build()
            .unwrap()
    }

    #[cfg(not(target_env = "sgx"))]
    fn new_tokio_runtime() -> tokio::runtime::Runtime {
        // Otherwise we use a fully-fledged Tokio runtime.
        tokio::runtime::Runtime::new().unwrap()
    }

    /// Create a new runtime call dispatcher.
    pub fn new(initializer: Box<dyn Initializer>, rak: Arc<RAK>) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(BACKLOG_SIZE);

        let dispatcher = Arc::new(Dispatcher {
            logger: get_logger("runtime/dispatcher"),
            queue_tx: tx,
            rak,
            abort_batch: Arc::new(AtomicBool::new(false)),
            state: Mutex::new(None),
            state_cond: Condvar::new(),
            tokio_runtime: Self::new_tokio_runtime(),
        });

        // Spawn the dispatcher processing thread.
        let d = dispatcher.clone();
        thread::spawn(move || {
            let _guard = AbortOnPanic;
            d.run(initializer, rx);
        });

        dispatcher
    }

    /// Start the dispatcher.
    pub fn start(&self, protocol: Arc<Protocol>, consensus_verifier: Box<dyn Verifier>) {
        let consensus_verifier = Arc::from(consensus_verifier);
        let mut s = self.state.lock().unwrap();
        *s = Some(ProtocolState {
            protocol,
            consensus_verifier,
        });
        self.state_cond.notify_one();
    }

    /// Queue a new request to be dispatched.
    pub fn queue_request(&self, ctx: Context, id: u64, body: Body) -> AnyResult<()> {
        self.queue_tx
            .blocking_send(Command::Request(ctx, id, body))?;
        Ok(())
    }

    /// Signals to dispatcher that it should abort and waits for the abort to
    /// complete.
    pub fn abort_and_wait(&self) -> AnyResult<()> {
        self.abort_batch.store(true, Ordering::SeqCst);
        // Queue an abort command and wait for it to be processed.
        let (tx, mut rx) = mpsc::channel(1);
        self.queue_tx.blocking_send(Command::Abort(tx))?;
        rx.blocking_recv();
        Ok(())
    }

    fn run(self: &Arc<Self>, initializer: Box<dyn Initializer>, mut rx: mpsc::Receiver<Command>) {
        // Wait for the state to be available.
        let ProtocolState {
            protocol,
            consensus_verifier,
        } = {
            let mut guard = self.state.lock().unwrap();
            while guard.is_none() {
                guard = self.state_cond.wait(guard).unwrap();
            }

            guard.take().unwrap()
        };

        // Create actual dispatchers for RPCs and transactions.
        info!(self.logger, "Starting the runtime dispatcher");
        let mut rpc_demux = RpcDemux::new(self.rak.clone());
        let mut rpc_dispatcher = RpcDispatcher::default();
        let pre_init_state = PreInitState {
            protocol: &protocol,
            rak: &self.rak,
            rpc_demux: &mut rpc_demux,
            rpc_dispatcher: &mut rpc_dispatcher,
            consensus_verifier: &consensus_verifier,
        };
        let post_init_state = initializer.init(pre_init_state);
        let mut txn_dispatcher = post_init_state
            .txn_dispatcher
            .unwrap_or_else(|| Box::new(TxnNoopDispatcher::default()));
        txn_dispatcher.set_abort_batch_flag(self.abort_batch.clone());

        let state = State {
            protocol: protocol.clone(),
            consensus_verifier: consensus_verifier.clone(),
            dispatcher: self.clone(),
            rpc_demux: Arc::new(Mutex::new(rpc_demux)),
            rpc_dispatcher: Arc::new(rpc_dispatcher),
            txn_dispatcher: Arc::from(txn_dispatcher),
            attestation_handler: attestation::Handler::new(
                self.rak.clone(),
                protocol.clone(),
                consensus_verifier,
                protocol.get_runtime_id(),
                protocol.get_config().version,
            ),
            cache_set: cache::CacheSet::new(protocol.clone()),
        };

        // Start the async message processing task.
        self.tokio_runtime.block_on(async move {
            while let Some(cmd) = rx.recv().await {
                // Process received command.
                match cmd {
                    Command::Request(ctx, id, request) => {
                        // Process request in its own task.
                        let state = state.clone();

                        tokio::spawn(async move {
                            let protocol = state.protocol.clone();
                            let dispatcher = state.dispatcher.clone();
                            let result = dispatcher.handle_request(state, ctx, request).await;

                            // Send response.
                            let response = match result {
                                Ok(body) => body,
                                Err(error) => Body::Error(error),
                            };
                            protocol.send_response(id, response).unwrap();
                        });
                    }
                    Command::Abort(tx) => {
                        // Request to abort processing.
                        tx.send(()).await.unwrap();
                    }
                }
            }
        });

        info!(self.logger, "Runtime call dispatcher is terminating");
    }

    async fn handle_request(
        self: &Arc<Self>,
        state: State,
        ctx: Context,
        request: Body,
    ) -> Result<Body, Error> {
        match request {
            // Attestation-related requests.
            #[cfg(target_env = "sgx")]
            Body::RuntimeCapabilityTEERakInitRequest { .. }
            | Body::RuntimeCapabilityTEERakReportRequest {}
            | Body::RuntimeCapabilityTEERakAvrRequest { .. }
            | Body::RuntimeCapabilityTEERakQuoteRequest { .. } => {
                Ok(state.attestation_handler.handle(ctx, request)?)
            }

            // RPC and transaction requests.
            Body::RuntimeRPCCallRequest { request } => {
                // RPC call.
                self.dispatch_rpc(
                    &state.rpc_demux,
                    &state.rpc_dispatcher,
                    &state.protocol,
                    &state.consensus_verifier,
                    ctx,
                    request,
                )
                .await
            }
            Body::RuntimeLocalRPCCallRequest { request } => {
                // Local RPC call.
                self.dispatch_local_rpc(
                    &state.rpc_dispatcher,
                    &state.protocol,
                    &state.consensus_verifier,
                    ctx,
                    request,
                )
                .await
            }
            Body::RuntimeExecuteTxBatchRequest {
                mode,
                consensus_block,
                round_results,
                io_root,
                inputs,
                splits,
                in_msgs,
                block,
                epoch,
                max_messages,
            } => {
                // Transaction execution.
                self.dispatch_txn(
                    ctx,
                    state.cache_set,
                    &state.txn_dispatcher,
                    &state.protocol,
                    io_root,
                    inputs.unwrap_or_default(),
                    splits,
                    in_msgs,
                    TxDispatchState {
                        mode,
                        consensus_block,
                        consensus_verifier: state.consensus_verifier,
                        header: block.header,
                        epoch,
                        round_results,
                        max_messages,
                        check_only: false,
                    },
                )
                .await
            }
            Body::RuntimeCheckTxBatchRequest {
                consensus_block,
                inputs,
                block,
                epoch,
                max_messages,
            } => {
                // Transaction check.
                self.dispatch_txn(
                    ctx,
                    state.cache_set,
                    &state.txn_dispatcher,
                    &state.protocol,
                    Hash::default(),
                    inputs,
                    None,
                    vec![],
                    TxDispatchState {
                        mode: ExecutionMode::Execute,
                        consensus_block,
                        consensus_verifier: state.consensus_verifier,
                        header: block.header,
                        epoch,
                        round_results: Default::default(),
                        max_messages,
                        check_only: true,
                    },
                )
                .await
            }
            Body::RuntimeQueryRequest {
                consensus_block,
                header,
                epoch,
                max_messages,
                method,
                args,
            } => {
                // Query.
                self.dispatch_query(
                    ctx,
                    state.cache_set,
                    &state.txn_dispatcher,
                    &state.protocol,
                    method,
                    args,
                    TxDispatchState {
                        mode: ExecutionMode::Execute,
                        consensus_block,
                        consensus_verifier: state.consensus_verifier,
                        header,
                        epoch,
                        round_results: Default::default(),
                        max_messages,
                        check_only: true,
                    },
                )
                .await
            }

            // Other requests.
            Body::RuntimeKeyManagerPolicyUpdateRequest { signed_policy_raw } => {
                // KeyManager policy update local RPC call.
                self.handle_km_policy_update(&state.rpc_dispatcher, ctx, signed_policy_raw)
            }
            Body::RuntimeConsensusSyncRequest { height } => state
                .consensus_verifier
                .sync(height)
                .map_err(Into::into)
                .map(|_| Body::RuntimeConsensusSyncResponse {}),

            _ => {
                error!(self.logger, "Unsupported request type");
                Err(Error::new("dispatcher", 1, "Unsupported request type"))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn dispatch_query(
        &self,
        ctx: Context,
        cache_set: cache::CacheSet,
        txn_dispatcher: &Arc<dyn TxnDispatcher>,
        protocol: &Arc<Protocol>,
        method: String,
        args: Vec<u8>,
        state: TxDispatchState,
    ) -> Result<Body, Error> {
        debug!(self.logger, "Received query request";
            "method" => &method,
            "state_root" => ?state.header.state_root,
            "round" => ?state.header.round,
        );

        // Verify that the runtime ID matches the block's namespace. This is a protocol violation
        // as the compute node should never change the runtime ID.
        if state.header.namespace != protocol.get_runtime_id() {
            return Err(Error::new(
                "dispatcher",
                1,
                &format!(
                    "block namespace does not match runtime id (namespace: {:?} runtime ID: {:?})",
                    state.header.namespace,
                    protocol.get_runtime_id(),
                ),
            ));
        }

        let protocol = protocol.clone();
        let txn_dispatcher = txn_dispatcher.clone();

        tokio::task::spawn_blocking(move || {
            // For queries we don't do any consensus layer integrity verification by default and it
            // is up to the runtime to decide whether this is critical on a query-by-query basis.
            let consensus_state = state
                .consensus_verifier
                .unverified_state(state.consensus_block.clone())?;

            let cache = cache_set.query(Root {
                namespace: state.header.namespace,
                version: state.header.round,
                root_type: RootType::State,
                hash: state.header.state_root,
            });
            let mut cache = cache.borrow_mut();
            let mut overlay = OverlayTree::new(cache.tree_mut());

            let txn_ctx = TxnContext::new(
                ctx.freeze(),
                protocol,
                &state.consensus_block,
                consensus_state,
                &mut overlay,
                &state.header,
                state.epoch,
                &state.round_results,
                state.max_messages,
                state.check_only,
                0,
                0,
            );

            txn_dispatcher
                .query(txn_ctx, &method, args)
                .map(|data| Body::RuntimeQueryResponse { data })
        })
        .await?
    }

    fn txn_check_batch(
        &self,
        ctx: Arc<Context>,
        protocol: Arc<Protocol>,
        overlay: &mut OverlayTree<Tree>,
        txn_dispatcher: &dyn TxnDispatcher,
        inputs: &TxnBatch,
        state: TxDispatchState,
        th_idx: u32,
        num_th: u32,
    ) -> Result<TxBatchResult, Error> {
        // For check-only we don't do any consensus layer integrity verification.
        let consensus_state = state
            .consensus_verifier
            .unverified_state(state.consensus_block.clone())?;

        let txn_ctx = TxnContext::new(
            ctx.clone(),
            protocol.clone(),
            &state.consensus_block,
            consensus_state,
            overlay,
            &state.header,
            state.epoch,
            &state.round_results,
            state.max_messages,
            state.check_only,
            th_idx,
            num_th,
        );
        let results = txn_dispatcher.check_batch(txn_ctx, &inputs)?;

        /*
        if protocol.get_config().persist_check_tx_state {
            // Commit results to in-memory tree so they persist for subsequent batches that are
            // based on the same block.
            let _ = overlay.commit(Context::create_child(&ctx)).unwrap();
        }
        */

        debug!(self.logger, "Transaction batch check complete");

        Ok(TxBatchResult::CheckResult {
            result: results,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn txn_execute_batch(
        &self,
        ctx: Arc<Context>,
        protocol: Arc<Protocol>,
        overlay: &mut OverlayTree<Tree>,
        txn_dispatcher: &dyn TxnDispatcher,
        inputs: &mut TxnBatch,
        in_msgs: &Vec<roothash::IncomingMessage>,
        state: TxDispatchState,
        th_idx: u32,
        num_th: u32,
    ) -> Result<TxBatchResult, Error> {
        // Verify consensus state and runtime state root integrity before execution.
        let consensus_state = state.consensus_verifier.verify(
            state.consensus_block.clone(),
            state.header.clone(),
            state.epoch,
        )?;
        // Ensure the runtime is still ready to process requests.
        protocol.ensure_initialized()?;

        let header = &state.header;

        let txn_ctx = TxnContext::new(
            ctx.clone(),
            protocol,
            &state.consensus_block,
            consensus_state,
            overlay,
            header,
            state.epoch,
            &state.round_results,
            state.max_messages,
            state.check_only,
            th_idx,
            num_th,
        );

        // Perform execution based on the passed mode.
        let results = match state.mode {
            ExecutionMode::Execute => {
                // Just execute the batch.
                txn_dispatcher.execute_batch(txn_ctx, inputs, &in_msgs)?
            }
            ExecutionMode::Schedule => {
                // Allow the runtime to arbitrarily update the batch.
                txn_dispatcher.schedule_and_execute_batch(txn_ctx, inputs, &in_msgs)?
            }
        };

        Ok(TxBatchResult::ExecuteResult {
            result: results,
        })
    }

    fn txn_execute_batch_final<T: FallibleMKVS + Sized>(
        &self,
        ctx: Arc<Context>,
        overlay: &mut OverlayTree<T>,
        txn_dispatcher: &dyn TxnDispatcher,
        inputs: &mut TxnBatch,
        splits: Vec<u32>,
        in_msgs: &Vec<roothash::IncomingMessage>,
        io_root: Hash,
        state: TxDispatchState,
        mut results: ExecuteBatchResult,
    ) -> Result<Body, Error> {
        let header = &state.header;

        // Finalize state.
        let (state_write_log, new_state_root) = overlay
            .commit_both(
                Context::create_child(&ctx),
                header.namespace,
                header.round + 1,
            )
            .expect("state commit must succeed");

        txn_dispatcher.finalize(new_state_root);

        // Generate I/O root. Since we already fetched the inputs we avoid the need
        // to fetch them again by generating the previous I/O tree (generated by the
        // transaction scheduler) from the inputs.
        let mut txn_tree = TxnTree::new(
            Box::new(NoopReadSyncer),
            Root {
                namespace: header.namespace,
                version: header.round + 1,
                root_type: RootType::IO,
                hash: Hash::empty_hash(),
            },
        );
        let mut hashes = Vec::new();
        for (batch_order, input) in inputs.drain(..).enumerate() {
            hashes.push(Hash::digest_bytes(&input));
            txn_tree
                .add_input(
                    Context::create_child(&ctx),
                    input,
                    batch_order.try_into().unwrap(),
                )
                .expect("add transaction must succeed");
        }

        let (input_write_log, input_io_root) = txn_tree
            .commit(Context::create_child(&ctx))
            .expect("io commit must succeed");

        assert!(
            state.mode != ExecutionMode::Execute || input_io_root == io_root,
            "dispatcher: I/O root inconsistent with inputs (expected: {:?} got: {:?})",
            io_root,
            input_io_root
        );

        for (tx_hash, result) in hashes.iter().zip(results.results.drain(..)) {
            txn_tree
                .add_output(
                    Context::create_child(&ctx),
                    *tx_hash,
                    result.output,
                    result.tags,
                )
                .expect("add transaction must succeed");
        }

        txn_tree
            .add_block_tags(Context::create_child(&ctx), results.block_tags)
            .expect("adding block tags must succeed");

        let (io_write_log, io_root) = txn_tree
            .commit(Context::create_child(&ctx))
            .expect("io commit must succeed");

        let header = ComputeResultsHeader {
            round: header.round + 1,
            previous_hash: header.encoded_hash(),
            io_root: Some(io_root),
            state_root: Some(new_state_root),
            messages_hash: Some(roothash::Message::messages_hash(&results.messages)),
            in_msgs_hash: Some(roothash::IncomingMessage::in_messages_hash(
                &in_msgs[..results.in_msgs_count],
            )),
            in_msgs_count: results.in_msgs_count.try_into().unwrap(),
        };

        // Since we've computed the batch, we can trust it.
        state
            .consensus_verifier
            .trust(&header)
            .expect("trusting a computed header must succeed");

        info!(self.logger, "Transaction batch execution complete";
            "previous_hash" => ?header.previous_hash,
            "io_root" => ?header.io_root,
            "state_root" => ?header.state_root,
            "messages_hash" => ?header.messages_hash,
            "in_msgs_hash" => ?header.in_msgs_hash,
        );

        let rak_sig = if self.rak.public_key().is_some() {
            self.rak
                .sign(
                    COMPUTE_RESULTS_HEADER_CONTEXT,
                    &cbor::to_vec(header.clone()),
                )
                .unwrap()
        } else {
            Signature::default()
        };

        Ok(Body::RuntimeExecuteTxBatchResponse {
            batch: ComputedBatch {
                header,
                io_write_log,
                state_write_log,
                rak_sig,
                messages: results.messages,
            },
            tx_hashes: hashes,
            tx_reject_hashes: results.tx_reject_hashes,
            tx_splits: splits,
            tx_input_root: input_io_root,
            tx_input_write_log: input_write_log,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn dispatch_txn(
        self: &Arc<Self>,
        ctx: Context,
        _cache_set: cache::CacheSet,
        txn_dispatcher: &Arc<dyn TxnDispatcher>,
        protocol: &Arc<Protocol>,
        io_root: Hash,
        inputs: TxnBatch,
        splits: Option<Vec<u32>>,
        in_msgs: Vec<roothash::IncomingMessage>,
        state: TxDispatchState,
    ) -> Result<Body, Error> {
        // Make sure to abort the process on panic during transaction processing as that indicates
        // a serious problem and should make sure to clean up the process.
        let _guard = AbortOnPanic;

        if !state.check_only {
          info!(self.logger, "Received transaction batch request";
            "state.mode" => format!("{:?}", state.mode),
            "header_type" => format!("{:?}", state.header.header_type),
            "state_root" => ?state.header.state_root,
            "io_root" => ?state.header.io_root,
            "round" => state.header.round,
            "round_results" => ?state.round_results,
            "tx_count" => inputs.len(),
            "in_msg_count" => in_msgs.len(),
            "check_only" => state.check_only,
            "splits" => format!("{:?}", splits),
          );
        }

        // Verify that the runtime ID matches the block's namespace. This is a protocol violation
        // as the compute node should never change the runtime ID.
        assert!(
            state.header.namespace == protocol.get_runtime_id(),
            "block namespace does not match runtime id (namespace: {:?} runtime ID: {:?})",
            state.header.namespace,
            protocol.get_runtime_id(),
        );

        let num_tx: usize = inputs.len();
        let mut num_th: usize = if num_tx < 20 {
            1
        } else if num_tx < 50 {
            2
        } else if num_tx < 200 {
            4
        } else if num_tx < 1000 {
            8
        } else {
            12
        };

        let batches: Vec<TxnBatch> = if num_th == 1 {
            vec![inputs]
        } else if state.check_only {
            //{{{
            let avg = num_tx / num_th;
            let mut left = num_tx % num_th;

            let mut th_idx: usize = 0;

            let mut count = avg;
            if left > 0 {
                left -= 1;
                count += 1;
            }

            let mut _batches: Vec<TxnBatch> = Vec::new();

            for _ in 0..num_th {
                _batches.push(TxnBatch::new(vec![]));
            }
            for i in 0..num_tx {
                _batches[th_idx].push(inputs[i as usize].clone());
                if _batches[th_idx].len() == count {
                    th_idx += 1;
                    count = avg;
                    if left > 0 {
                        left -= 1;
                        count += 1;
                    }
                }
            }
            //}}}
            _batches
        } else if state.mode == ExecutionMode::Execute {
            //{{{
            assert!(
                splits.is_some(),
                "splits is none when ExecutionMode is Execute, num of txs is {:?}",
                inputs.len(),
            );

            let splits = splits.unwrap();
            let total = splits.iter().fold(0, |acc, &x| acc + x);
            assert!(
                total == inputs.len() as u32,
                "splits sum {:?} is different from inputs length {:?}",
                total,
                inputs.len(),
            );

            let mut _batches: Vec<TxnBatch> = Vec::new();
            let mut tx_idx = 0;

            for n in 0..splits.len() {
                _batches.push(TxnBatch::new(vec![]));
                for _ in 0..splits[n] as usize {
                    _batches[n].push(inputs[tx_idx].clone());
                    tx_idx += 1;
                }
            }

            num_th = _batches.len();
            //}}}
            _batches
        } else {
            //{{{
            let mut _batches: Vec<TxnBatch> = txn_dispatcher.split_txn_batch(&inputs, num_th)?;

            if _batches[0].len() > 0 {
                info!(self.logger, "has exclusive tx";
                    "num" => _batches[0].len(),
                );
            } else if _batches.len() == 2 {
                _batches.remove(0);
            }

            if _batches.len() > 2 {
                _batches.push(TxnBatch::new(vec![]));
            }

            num_th = _batches.len();

            //}}}
            _batches
        };

        if !state.check_only {
            let splits: Vec<u32> = batches.iter().map(|x| x.len() as u32).collect();
            info!(self.logger, "dispatch_txn tx splits";
                "splits" => format!("{:?}", splits),
            );
        }

        let th_inputs:  Arc<Mutex<Vec<TxnBatch>>>                       = Arc::new(Mutex::new(batches));
        let th_in_msgs: Arc<Mutex<Vec<Vec<roothash::IncomingMessage>>>> = Arc::new(Mutex::new(vec![in_msgs]));
        let th_overlay: Arc<Mutex<Vec<OverlayTree<Tree>>>>              = Arc::new(Mutex::new(vec![]));

        let root = Root {
            namespace: state.header.namespace,
            version: state.header.round,
            root_type: RootType::State,
            hash: state.header.state_root,
        };

        let check_only = state.check_only;
        let index_base: i32 = if check_only {
            100
        } else {
            0
        };

        let mut reuse_tree: Option<Tree> = None;

        {
            let mut tree_container = if state.check_only {
                CHECK_TREE.lock().unwrap()
            } else {
                EXECUTE_TREE.lock().unwrap()
            };

            //remove the base tree if root not match
            if tree_container.is_some() {
                let tree_root = tree_container.as_ref().unwrap().get_root();
                if tree_root.hash == root.hash && tree_root.version != root.version {
                    if !state.check_only {
                      warn!(self.logger, "dispatch_txn set tree root due to same hash but diff version";
                        "hash" => ?root.hash,
                        "tree root version" => tree_root.version,
                        "root version" => root.version,
                      );
                    }

                    tree_container.as_mut().unwrap().set_root(root.clone());
                }

                if tree_container.as_ref().unwrap().get_root() == root {
                    if num_th == 1 {
                        reuse_tree = tree_container.take();
                    }
                } else {
                    tree_container.take();
                }
            }
        }

        for i in 0..num_th as i32 {
            if i != 0 {
                th_in_msgs.lock().unwrap().push(vec![]);
            }

            let overlay: OverlayTree<Tree> = if reuse_tree.is_some() {
                OverlayTree::new(reuse_tree.take().unwrap())
            } else if state.check_only {
                OverlayTree::state_new(
                    cache::Cache::host_cache_build(&protocol.clone(), root, CHECK_TREE.clone(), index_base+i+1),
                    index_base+i+1
                )
                //OverlayTree::new(cache::Cache::build(&protocol.clone(), root))
            } else {
                OverlayTree::state_new(
                    cache::Cache::host_cache_build(&protocol.clone(), root, EXECUTE_TREE.clone(), index_base+i+1),
                    index_base+i+1
                )
                //OverlayTree::new(cache::Cache::build(&protocol.clone(), root))
            };

            th_overlay.lock().unwrap().push(overlay);
        }

        let ctx = ctx.freeze();

        let th_disp = |i| {
            //{{{
            let ctx = Context::create_child(&ctx).freeze();
            let protocol = protocol.clone();
            let dispatcher = self.clone();
            let txn_dispatcher = txn_dispatcher.clone();
            let state = TxDispatchState {
                mode: state.mode.clone(),
                consensus_block: state.consensus_block.clone(),
                consensus_verifier: state.consensus_verifier.clone(),
                header: state.header.clone(),
                epoch: state.epoch,
                round_results: state.round_results.clone(),
                max_messages: state.max_messages,
                check_only: state.check_only,
            };

            let th_inputs = Arc::clone(&th_inputs);
            let th_in_msgs = Arc::clone(&th_in_msgs);
            let th_overlay = Arc::clone(&th_overlay);

            let (sender, receiver) = std_mpsc::channel();

            let x = 
            tokio::task::spawn_blocking(move || {
                //{{{
                let mut inputs = th_inputs.lock().unwrap().remove(0);
                let in_msgs = th_in_msgs.lock().unwrap().remove(0);
                let mut overlay = th_overlay.lock().unwrap().remove(0);

                let _ = sender.send(i).expect("notify must send");

                let r =
                if check_only {
                    dispatcher.txn_check_batch(Context::create_child(&ctx).freeze(), protocol, &mut overlay, &txn_dispatcher, &inputs, state, i as u32, num_th as u32)
                } else {
                    dispatcher.txn_execute_batch(
                        Context::create_child(&ctx).freeze(),
                        protocol,
                        &mut overlay,
                        &txn_dispatcher,
                        &mut inputs,
                        &in_msgs,
                        state,
                        i as u32,
                        num_th as u32,
                    )
                };

                let r = match r {
                    Ok(value) => {
                        Ok(match value {
                            TxBatchResult::CheckResult{result} => {
                                TxBatchResult::CheckResult {
                                    result
                                }
                            },
                            TxBatchResult::ExecuteResult{result} => {
                                TxBatchResult::ExecuteResult {
                                    result
                                }
                            }
                        })
                    },
                    Err(err) => Err(err)
                };

                (i, r, overlay, inputs, in_msgs)
                //}}}
            });

            let v = receiver.recv();
            assert!(
                v.unwrap() == i,
                "receive th idx is different from sent",
            );

            x
            //}}}
        };

        let mut i: usize = 0;
        let mut returns = vec![];

        if !check_only {
            let handle = th_disp(i);
            i += 1;
            returns.push(handle
                .await
                .unwrap() // Propagate panics during transaction dispatch.
            );
        }

        let mut handles = vec![];
        while i < num_th {
            handles.push(th_disp(i));
            i += 1;
            if !check_only && i == num_th-1 {
                break;
            }
        }
        for handle in handles {
            returns.push(handle
                .await
                .unwrap() // Propagate panics during transaction dispatch.
            );
        }

        if !check_only && i == num_th-1 {
            let handle = th_disp(i);
            returns.push(handle
                .await
                .unwrap() // Propagate panics during transaction dispatch.
            );
        }

        assert!(th_inputs.lock().unwrap().len() == 0 && th_in_msgs.lock().unwrap().len() == 0,
            "th_inputs len or th_in_msg len is not 0 after taken by threads!",
        );

        let mut th_overlay = th_overlay.lock().unwrap();

        let mut splits: Vec<u32> = Vec::new();

        let mut all_inputs: TxnBatch = TxnBatch::new(Vec::<Vec<u8>>::new());
        let mut all_in_msgs: Vec<roothash::IncomingMessage> = vec![];

        let mut check_results: Vec<CheckTxResult> = vec![];

        let mut execute_results = ExecuteBatchResult {
            results: vec![],
            messages: vec![],
            in_msgs_count: 0,
            block_tags: vec![],
            tx_reject_hashes: vec![],
        };

        for (
            _th_idx, r, 
            overlay, mut inputs, mut in_msgs 
        ) in returns {
            match r {
                Ok(value) => {
                    match value {
                        TxBatchResult::CheckResult{mut result} => {
                            check_results.append(&mut result);
                        },
                        TxBatchResult::ExecuteResult{mut result} => {
                            execute_results.results.append(&mut result.results);
                            execute_results.messages.append(&mut result.messages);
                            execute_results.in_msgs_count += result.in_msgs_count;
                            execute_results.block_tags.append(&mut result.block_tags);
                            execute_results.tx_reject_hashes.append(&mut result.tx_reject_hashes);
                        }
                    }
                },
                Err(err) => return Err(err),
            }
            th_overlay.push(overlay);

            if state.mode == ExecutionMode::Schedule {
                splits.push(inputs.len() as u32);
            }
            all_inputs.append(&mut inputs);
            all_in_msgs.append(&mut in_msgs);
        }

        if !check_only {
            warn!(self.logger, "_dispatch_txn";
                "state.mode" => format!("{:?}", state.mode),
                "inputs before execute" => num_tx,
                "inputs after execute" => all_inputs.len(),
                "reject_txs" => execute_results.tx_reject_hashes.len(),
                "return splts" => format!("{:?}", splits),
            );
        }

        let mut state_overlay: OverlayTree<Tree> = if num_th == 1 {
            th_overlay.remove(0)
        } else {
            let tree = {
                let mut tree_container = if state.check_only {
                    CHECK_TREE.lock().unwrap()
                } else {
                    EXECUTE_TREE.lock().unwrap()
                };

                if tree_container.is_none() {
                    drop(tree_container);
                    cache::Cache::host_cache_build(&protocol.clone(), root, Arc::new(Mutex::new(None)), index_base)
                } else {
                    tree_container.take().unwrap()
                }
            };
            OverlayTree::state_new(tree, index_base)
        };

        if num_th > 1 {
            for _ in 0..num_th {
                OverlayTree::merge(&mut th_overlay.remove(0), &mut state_overlay);
            }
        }

        let ret = if state.check_only {
            if protocol.get_config().persist_check_tx_state {
                //let mut cache = cache_set.check(root);
                //let mut cache_overlay = OverlayTree::new(cache.tree_mut());
                // Commit results to in-memory tree so they persist for subsequent batches that are
                // based on the same block.
                //let _ = cache_overlay.commit(Context::create_child(&ctx)).unwrap();
            }
            Ok(Body::RuntimeCheckTxBatchResponse {results: check_results})
        } else {
            //let cache = cache_set.execute(root);
            //let mut overlay = merged_overlay.lock().unwrap().remove(0);
            self.txn_execute_batch_final(ctx, &mut state_overlay, txn_dispatcher, &mut all_inputs, splits, &all_in_msgs, io_root, state, execute_results)
        };

        let tree = state_overlay.take_tree();
        let mut tree_container = if check_only {
            CHECK_TREE.lock().unwrap()
        } else {
            EXECUTE_TREE.lock().unwrap()
        };
        tree_container.replace(tree);

        ret
    }

    async fn dispatch_rpc(
        &self,
        rpc_demux: &Arc<Mutex<RpcDemux>>,
        rpc_dispatcher: &Arc<RpcDispatcher>,
        protocol: &Arc<Protocol>,
        consensus_verifier: &Arc<dyn Verifier>,
        ctx: Context,
        request: Vec<u8>,
    ) -> Result<Body, Error> {
        debug!(self.logger, "Received RPC call request");

        // Process frame.
        let mut buffer = vec![];
        let result = rpc_demux
            .lock()
            .unwrap()
            .process_frame(request, &mut buffer)
            .map_err(|err| {
                error!(self.logger, "Error while processing frame"; "err" => %err);
                Error::new("rhp/dispatcher", 1, &format!("{}", err))
            })?;

        if let Some((session_id, session_info, message, untrusted_plaintext)) = result {
            // Dispatch request.
            assert!(
                buffer.is_empty(),
                "must have no handshake data in transport mode"
            );

            match message {
                RpcMessage::Request(req) => {
                    // First make sure that the untrusted_plaintext matches
                    // the request's method!
                    if untrusted_plaintext != req.method {
                        error!(self.logger, "Request methods don't match!";
                            "untrusted_plaintext" => ?untrusted_plaintext,
                            "method" => ?req.method
                        );
                        return Err(Error::new(
                            "rhp/dispatcher",
                            1,
                            "Request's method doesn't match untrusted_plaintext copy.",
                        ));
                    }

                    // Request, dispatch.
                    let ctx = ctx.freeze();
                    let rak = self.rak.clone();
                    let protocol = protocol.clone();
                    let consensus_verifier = consensus_verifier.clone();
                    let rpc_dispatcher = rpc_dispatcher.clone();

                    let response = tokio::task::spawn_blocking(move || {
                        let untrusted_local = Arc::new(ProtocolUntrustedLocalStorage::new(
                            Context::create_child(&ctx),
                            protocol.clone(),
                        ));
                        let rpc_ctx = RpcContext::new(
                            ctx.clone(),
                            rak,
                            session_info,
                            consensus_verifier,
                            &untrusted_local,
                        );
                        let response = rpc_dispatcher.dispatch(req, rpc_ctx);
                        RpcMessage::Response(response)
                    })
                    .await?;

                    // Note: MKVS commit is omitted, this MUST be global side-effect free.

                    debug!(self.logger, "RPC call dispatch complete");

                    let mut buffer = vec![];
                    rpc_demux
                        .lock()
                        .unwrap()
                        .write_message(session_id, response, &mut buffer)
                        .map_err(|err| {
                            error!(self.logger, "Error while writing response"; "err" => %err);
                            Error::new("rhp/dispatcher", 1, &format!("{}", err))
                        })
                        .map(|_| Body::RuntimeRPCCallResponse { response: buffer })
                }
                RpcMessage::Close => {
                    // Session close.
                    let mut buffer = vec![];
                    rpc_demux
                        .lock()
                        .unwrap()
                        .close(session_id, &mut buffer)
                        .map_err(|err| {
                            error!(self.logger, "Error while closing session"; "err" => %err);
                            Error::new("rhp/dispatcher", 1, &format!("{}", err))
                        })
                        .map(|_| Body::RuntimeRPCCallResponse { response: buffer })
                }
                msg => {
                    warn!(self.logger, "Ignoring invalid RPC message type"; "msg" => ?msg);
                    Err(Error::new("rhp/dispatcher", 1, "invalid RPC message type"))
                }
            }
        } else {
            // Send back any handshake frames.
            Ok(Body::RuntimeRPCCallResponse { response: buffer })
        }
    }

    async fn dispatch_local_rpc(
        self: &Arc<Self>,
        rpc_dispatcher: &Arc<RpcDispatcher>,
        protocol: &Arc<Protocol>,
        consensus_verifier: &Arc<dyn Verifier>,
        ctx: Context,
        request: Vec<u8>,
    ) -> Result<Body, Error> {
        // Make sure to abort the process on panic during local RPC processing as that indicates a
        // serious problem and should make sure to clean up the process.
        let _guard = AbortOnPanic;

        debug!(self.logger, "Received local RPC call request");

        let req: RpcRequest = cbor::from_slice(&request)
            .map_err(|_| Error::new("rhp/dispatcher", 1, "malformed request"))?;

        // Request, dispatch.
        let ctx = ctx.freeze();
        let protocol = protocol.clone();
        let dispatcher = self.clone();
        let rpc_dispatcher = rpc_dispatcher.clone();
        let consensus_verifier = consensus_verifier.clone();

        tokio::task::spawn_blocking(move || {
            let untrusted_local = Arc::new(ProtocolUntrustedLocalStorage::new(
                Context::create_child(&ctx),
                protocol.clone(),
            ));
            let rpc_ctx = RpcContext::new(
                ctx.clone(),
                dispatcher.rak.clone(),
                None,
                consensus_verifier,
                &untrusted_local,
            );
            let response = rpc_dispatcher.dispatch_local(req, rpc_ctx);
            let response = RpcMessage::Response(response);

            // Note: MKVS commit is omitted, this MUST be global side-effect free.

            debug!(dispatcher.logger, "Local RPC call dispatch complete");

            let response = cbor::to_vec(response);
            Ok(Body::RuntimeLocalRPCCallResponse { response })
        })
        .await
        .unwrap() // Propagate panics during local RPC dispatch.
    }

    fn handle_km_policy_update(
        &self,
        rpc_dispatcher: &RpcDispatcher,
        _ctx: Context,
        signed_policy_raw: Vec<u8>,
    ) -> Result<Body, Error> {
        // Make sure to abort the process on panic during policy processing as that indicates a
        // serious problem and should make sure to clean up the process.
        let _guard = AbortOnPanic;

        debug!(self.logger, "Received km policy update request");
        rpc_dispatcher.handle_km_policy_update(signed_policy_raw);
        debug!(self.logger, "KM policy update request complete");

        Ok(Body::RuntimeKeyManagerPolicyUpdateResponse {})
    }
}
