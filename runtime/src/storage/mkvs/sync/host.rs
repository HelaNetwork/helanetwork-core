use std::{any::Any, sync::{Arc, Mutex}};

use anyhow::Result;
use io_context::Context;

use crate::{
    protocol::{Protocol, ProtocolError},
    storage::mkvs::sync::*,
    storage::mkvs::Tree,
    types::{
        Body, HostStorageEndpoint, StorageSyncRequest, StorageSyncRequestWithEndpoint,
        StorageSyncResponse,
    },
};

/// A proxy read syncer which forwards calls to the runtime host.
pub struct HostReadSyncer {
    protocol: Arc<Protocol>,
    endpoint: HostStorageEndpoint,
    use_cache: bool,
    tree_cache: Arc<Mutex<Option<Tree>>>,
    pub index: i32,
}

impl HostReadSyncer {
    /// Construct a new host proxy instance.
    pub fn new(protocol: Arc<Protocol>, endpoint: HostStorageEndpoint) -> HostReadSyncer {
        HostReadSyncer { protocol, endpoint, use_cache: false, tree_cache: Arc::new(Mutex::new(None)), index: -1, }
    }

    pub fn cache_new(protocol: Arc<Protocol>, endpoint: HostStorageEndpoint, tree: Arc<Mutex<Option<Tree>>>, index: i32) -> HostReadSyncer {
        HostReadSyncer { protocol, endpoint, use_cache: (index > 0 && index < 100) || index > 100, tree_cache: tree, index, }
    }

    fn call_host_with_proof(
        &self,
        ctx: Context,
        request: StorageSyncRequest,
    ) -> Result<ProofResponse> {
        let request = Body::HostStorageSyncRequest(StorageSyncRequestWithEndpoint {
            endpoint: self.endpoint,
            request,
        });
        match self.protocol.call_host(ctx, request) {
            Ok(Body::HostStorageSyncResponse(StorageSyncResponse::ProofResponse(response))) => {
                Ok(response)
            }
            Ok(_) => Err(ProtocolError::InvalidResponse.into()),
            Err(error) => Err(error.into()),
        }
    }
}

impl ReadSync for HostReadSyncer {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn sync_get(&mut self, ctx: Context, request: GetRequest) -> Result<ProofResponse> {
        self.call_host_with_proof(ctx, StorageSyncRequest::SyncGet(request))
    }

    fn cache_get(&mut self, ctx: Context, request: GetRequest) -> Option<NodePtrRef> {
        if self.use_cache && !request.include_siblings {
            let tree = self.tree_cache.lock().unwrap();
            if tree.is_some() {
                return tree.as_ref().unwrap().copy(ctx, &request.key, &request.tree.position);
            }
        }
        None
    }

    fn sync_get_prefixes(
        &mut self,
        ctx: Context,
        request: GetPrefixesRequest,
    ) -> Result<ProofResponse> {
        self.call_host_with_proof(ctx, StorageSyncRequest::SyncGetPrefixes(request))
    }

    fn sync_iterate(&mut self, ctx: Context, request: IterateRequest) -> Result<ProofResponse> {
        self.call_host_with_proof(ctx, StorageSyncRequest::SyncIterate(request))
    }

    fn get_index(&self) -> i32 {
        return self.index;
    }
}
