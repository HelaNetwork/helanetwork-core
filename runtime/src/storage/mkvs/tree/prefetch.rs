use anyhow::Result;
use io_context::Context;

use crate::storage::mkvs::{cache::*, sync::*, tree::*, Prefix};

pub(super) struct FetcherSyncGetPrefixes<'a> {
    prefixes: &'a [Prefix],
    limit: u16,
}

impl<'a> FetcherSyncGetPrefixes<'a> {
    pub(super) fn new(prefixes: &'a [Prefix], limit: u16) -> Self {
        Self { prefixes, limit }
    }
}

impl<'a> ReadSyncFetcher for FetcherSyncGetPrefixes<'a> {
    fn fetch(
        &self,
        ctx: Context,
        root: Root,
        ptr: NodePtrRef,
        rs: &mut Box<dyn ReadSync>,
    ) -> Result<Proof> {
        let rsp = rs.sync_get_prefixes(
            ctx,
            GetPrefixesRequest {
                tree: TreeID {
                    root,
                    position: ptr.borrow().hash,
                },
                prefixes: self.prefixes.to_vec(),
                limit: self.limit,
            },
        )?;
        Ok(rsp.proof)
    }

    fn key(
        &self,
    ) -> Key {
        Vec::new()
    }
}

impl Tree {
    /// Populate the in-memory tree with nodes for keys starting with given prefixes.
    pub fn prefetch_prefixes(&self, ctx: Context, prefixes: &[Prefix], limit: u16) -> Result<()> {
        let ctx = ctx.freeze();
        let pending_root = self.cache.borrow().get_pending_root();
        self.cache.borrow_mut().remote_sync(
            &ctx,
            pending_root,
            FetcherSyncGetPrefixes::new(prefixes, limit),
        )
    }
}
