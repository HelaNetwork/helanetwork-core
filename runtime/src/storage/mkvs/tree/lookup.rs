use std::sync::Arc;

use anyhow::{anyhow,Result};
use io_context::Context;

use crate::storage::mkvs::{cache::*, sync::*, tree::*};
use crate::common::crypto::hash::Hash;

pub(super) struct FetcherSyncGet<'a> {
    key: &'a Key,
    include_siblings: bool,
}

impl<'a> FetcherSyncGet<'a> {
    pub(super) fn new(key: &'a Key, include_siblings: bool) -> Self {
        Self {
            key,
            include_siblings,
        }
    }
}

impl<'a> ReadSyncFetcher for FetcherSyncGet<'a> {
    fn fetch(
        &self,
        ctx: Context,
        root: Root,
        ptr: NodePtrRef,
        rs: &mut Box<dyn ReadSync>,
    ) -> Result<Proof> {
        let rsp = rs.sync_get(
            ctx,
            GetRequest {
                tree: TreeID {
                    root,
                    position: ptr.borrow().hash,
                },
                key: self.key.clone(),
                include_siblings: self.include_siblings,
            },
        )?;
        Ok(rsp.proof)
    }

    fn fetch_by_cache(
        &self,
        ctx: Context,
        root: Root,
        ptr: NodePtrRef,
        rs: &mut Box<dyn ReadSync>,
    ) -> Option<NodePtrRef> {
        rs.cache_get(
            ctx,
            GetRequest {
                tree: TreeID {
                    root,
                    position: ptr.borrow().hash,
                },
                key: self.key.clone(),
                include_siblings: self.include_siblings,
            },
        )
    }

    fn key(
        &self,
    ) -> Key {
        self.key.clone()
    }
}

impl Tree {
    /// Get an existing key.
    pub fn get(&self, ctx: Context, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let r = self._get_top(ctx, key, false)?;
        self.key_set.borrow_mut().insert(key.to_vec());
        Ok(r)
    }

    pub fn merge(source: &Self, target: &Tree, key: &Vec<u8>) -> Result<()> {
        let src_root = source.cache.borrow().get_pending_root();
        let dst_root = target.cache.borrow().get_pending_root();

        let r = Tree::_merge(src_root, dst_root, 0, key, 0)?;
        target.key_set.borrow_mut().insert(key.clone());
        Ok(r)
    }

    pub fn copy(&self, ctx: Context, key: &Vec<u8>, position: &Hash) -> Option<NodePtrRef> {
        if !self.key_set.borrow().contains(key) {
            return None;
        }

        let ctx = ctx.freeze();
        let pending_root = self.cache.borrow().get_pending_root();

        //self.cache.borrow_mut().mark_position();
        let target: NodePtrRef = NodePointer::hash_ptr(*position);

        if self._copy(&ctx, pending_root, 0, &key, 0, target.clone()) {
            Some(target)
        } else {
            None
        }
    }

    /// Check if the key exists in the local cache.
    pub fn cache_contains_key(&self, ctx: Context, key: &[u8]) -> bool {
        match self._get_top(ctx, key, true) {
            Ok(Some(_)) => true,
            Ok(None) => false,
            Err(_) => false,
        }
    }

    fn _get_top(&self, ctx: Context, key: &[u8], check_only: bool) -> Result<Option<Vec<u8>>> {
        let ctx = ctx.freeze();
        let boxed_key = key.to_vec();
        let pending_root = self.cache.borrow().get_pending_root();

        // Remember where the path from root to target node ends (will end).
        self.cache.borrow_mut().mark_position();

        self._get(&ctx, pending_root, 0, &boxed_key, 0, check_only)
    }

    fn _get(
        &self,
        ctx: &Arc<Context>,
        ptr: NodePtrRef,
        bit_depth: Depth,
        key: &Key,
        depth: Depth,
        check_only: bool,
    ) -> Result<Option<Value>> {
        let node_ref = self.cache.borrow_mut().deref_node_ptr(
            ctx,
            ptr,
            if check_only {
                None
            } else {
                Some(FetcherSyncGet::new(key, false))
            },
        )?;

        match classify_noderef!(?node_ref) {
            NodeKind::None => {
                // Reached a nil node, there is nothing here.
                Ok(None)
            }
            NodeKind::Internal => {
                let node_ref = node_ref.unwrap();
                if let NodeBox::Internal(ref mut n) = *node_ref.borrow_mut() {
                    // Internal node.
                    // Does lookup key end here? Look into LeafNode.
                    if key.bit_length() == bit_depth + n.label_bit_length {
                        return self._get(
                            ctx,
                            n.leaf_node.clone(),
                            bit_depth + n.label_bit_length,
                            key,
                            depth,
                            check_only,
                        );
                    }

                    // Lookup key is too short for the current n.Label. It's not stored.
                    if key.bit_length() < bit_depth + n.label_bit_length {
                        return Ok(None);
                    }

                    // Continue recursively based on a bit value.
                    if key.get_bit(bit_depth + n.label_bit_length) {
                        return self._get(
                            ctx,
                            n.right.clone(),
                            bit_depth + n.label_bit_length,
                            key,
                            depth + 1,
                            check_only,
                        );
                    } else {
                        return self._get(
                            ctx,
                            n.left.clone(),
                            bit_depth + n.label_bit_length,
                            key,
                            depth + 1,
                            check_only,
                        );
                    }
                }

                unreachable!("node kind is internal node");
            }
            NodeKind::Leaf => {
                // Reached a leaf node, check if key matches.
                let node_ref = node_ref.unwrap();
                if noderef_as!(node_ref, Leaf).key == *key {
                    Ok(Some(noderef_as!(node_ref, Leaf).value.clone()))
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn _copy(
        &self,
        ctx: &Arc<Context>,
        ptr: NodePtrRef,
        bit_depth: Depth,
        key: &Key,
        depth: Depth,
        target: NodePtrRef,
    ) -> bool {
        let ptr_ref = ptr.borrow();
        let mut target_ref = target.borrow_mut();

        let node_ref = ptr_ref.node.clone();
        if !node_ref.is_some() {
            return false;
        }

        match *node_ref.unwrap().borrow() {
            NodeBox::Internal(ref n) => {
                let mut same = false;
                if ptr_ref.hash == target_ref.hash {
                    same = true;
                    target_ref.node = Some(Rc::new(RefCell::new(NodeBox::Internal(InternalNode {
                        clean: true,
                        hash: n.hash.clone(),
                        label: n.label.clone(),
                        label_bit_length: n.label_bit_length,
                        leaf_node: NodePointer::hash_ptr(n.leaf_node.borrow().hash),
                        left: NodePointer::hash_ptr(n.left.borrow().hash),
                        right: NodePointer::hash_ptr(n.right.borrow().hash),
                    }))));
                }

                // Does lookup key end here? Look into LeafNode.
                if key.bit_length() == bit_depth + n.label_bit_length {
                    let next = if same {
                        noderef_as!(target_ref.node.as_ref().unwrap(), Internal).leaf_node.clone()
                    } else {
                        target.clone()
                    };
                    drop(target_ref);
                    return self._copy(
                        ctx,
                        n.leaf_node.clone(),
                        bit_depth + n.label_bit_length, // should be bit_depth?
                        key,
                        depth,
                        next,
                    );
                }

                // Lookup key is too short for the current n.Label. It's not stored.
                if key.bit_length() < bit_depth + n.label_bit_length {
                    return false;
                }

                // Continue recursively based on a bit value.
                if key.get_bit(bit_depth + n.label_bit_length) {
                    let next = if same {
                        noderef_as!(target_ref.node.as_ref().unwrap(), Internal).right.clone()
                    } else {
                        target.clone()
                    };
                    drop(target_ref);
                    self._copy(
                        ctx,
                        n.right.clone(),
                        bit_depth + n.label_bit_length,
                        key,
                        depth + 1,
                        next,
                    )
                } else {
                    let next = if same {
                        noderef_as!(target_ref.node.as_ref().unwrap(), Internal).left.clone()
                    } else {
                        target.clone()
                    };
                    drop(target_ref);
                    self._copy(
                        ctx,
                        n.left.clone(),
                        bit_depth + n.label_bit_length,
                        key,
                        depth + 1,
                        next,
                    )
                }
            }
            NodeBox::Leaf(ref n) => {
                if n.key == *key {
                    if ptr_ref.hash == target_ref.hash {
                        target_ref.node = Some(Rc::new(RefCell::new(NodeBox::Leaf(LeafNode {
                            clean: true,
                            hash: n.hash.clone(),
                            key: n.key.clone(),
                            value: n.value.clone(),
                        }))));
                        return true;
                    }
                }
                false
            }
        }
    }

    fn _merge(
        src_ptr: NodePtrRef,
        dst_ptr: NodePtrRef,
        bit_depth: Depth,
        key: &Key,
        depth: Depth,
    ) -> Result<()> {

        let src_pt = src_ptr.borrow();
        let dst_pt = dst_ptr.borrow();

        if src_pt.hash != dst_pt.hash {
            return Err(anyhow!("mismatch"));
        }

        //cut and return the node with the hash
        if src_pt.node.is_some() && dst_pt.node.is_none() {
            drop(src_pt);
            drop(dst_pt);
            let mut src_pt = src_ptr.borrow_mut();
            let mut dst_pt = dst_ptr.borrow_mut();
            dst_pt.node = src_pt.node.take();
            return Ok(());
        }

        if src_pt.node.is_none() {
            return Ok(());
        }

        let src_node_ref = src_pt.node.clone();
        let dst_node_ref = dst_pt.node.clone().unwrap();

        match *src_node_ref.unwrap().borrow() {
            NodeBox::Internal(ref n) => {
                if key.bit_length() == bit_depth + n.label_bit_length {
                    return Self::_merge(
                        n.leaf_node.clone(),
                        noderef_as!(dst_node_ref, Internal).leaf_node.clone(),
                        bit_depth + n.label_bit_length, // should be bit_depth?
                        key,
                        depth,
                    );
                }

                // Lookup key is too short for the current n.Label. It's not stored.
                if key.bit_length() < bit_depth + n.label_bit_length {
                    //return Err(anyhow!("key too short"));
                    return Ok(());
                }

                // Continue recursively based on a bit value.
                if key.get_bit(bit_depth + n.label_bit_length) {
                    Self::_merge(
                        n.right.clone(),
                        noderef_as!(dst_node_ref, Internal).right.clone(),
                        bit_depth + n.label_bit_length,
                        key,
                        depth + 1,
                    )
                } else {
                    Self::_merge(
                        n.left.clone(),
                        noderef_as!(dst_node_ref, Internal).left.clone(),
                        bit_depth + n.label_bit_length,
                        key,
                        depth + 1,
                    )
                }
            }
            NodeBox::Leaf(ref _n) => {
                Ok(())
            }
        }
    }
}
