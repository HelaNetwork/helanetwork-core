use std::thread;
use anyhow::Result;
use io_context::Context;

use crate::{
    common::{crypto::hash::Hash, namespace::Namespace},
    storage::mkvs::{cache::*, tree::*},
};

#[derive(Debug)]
struct ThreadParam {
    ptr: NodePtrRef, 
    sub_thread: bool,
}

unsafe impl Send for ThreadParam {}

const THREAD_DEPTHS: u16 = 3;

impl Tree {
    /// Commit tree updates to the underlying database and return
    /// the write log and new merkle root.
    pub fn commit(&mut self, _ctx: Context, namespace: Namespace, version: u64) -> Result<Hash> {
        let mut update_list: UpdateList<LRUCache> = UpdateList::new();
        let pending_root = self.cache.borrow().get_pending_root();
        let new_hash = _commit(pending_root, &mut update_list)?;

        update_list.commit(&mut self.cache.borrow_mut());

        self.cache.borrow_mut().set_sync_root(Root {
            namespace,
            version,
            root_type: self.root_type,
            hash: new_hash,
        });

        Ok(new_hash)
    }

    pub fn multi_commit(&mut self, _ctx: Context, namespace: Namespace, version: u64, kvs_dist: &Option<Vec<usize>>) -> Result<Hash> {
        let mut handles: Vec<thread::JoinHandle<()>> = vec![];
        let total_kvs = if kvs_dist.is_some() {
            kvs_dist.as_ref().unwrap().iter().fold(0, |acc, x| acc + x)
        } else {
            0
        };

        let pending_root = self.cache.borrow().get_pending_root();

        let _ = _dispatch_commit(pending_root, 0, 0, &mut |ptr, index| {
            let mut sub_thread = false;
            if kvs_dist.is_some() {
                let v = kvs_dist.as_ref().unwrap();
                if index < v.len() && v[index] > total_kvs/2 && v[index] > 500 {
                    sub_thread = true;
                }
            }

            let tp = ThreadParam {
                ptr,
                sub_thread,
            };

            let handle = thread::spawn(move || {
                let ptr: NodePtrRef = tp.ptr;
                if tp.sub_thread {
                    let _ = sub_multi_commit(ptr);
                } else {
                    let _ = _multi_commit(ptr);
                }
            });

            handles.push(handle);
        });

        while handles.len() > 0 {
            let _ = handles.remove(0).join();
        }

        let mut update_list: UpdateList<LRUCache> = UpdateList::new();
        let pending_root = self.cache.borrow().get_pending_root();
        let new_hash = _commit(pending_root, &mut update_list)?;

        update_list.commit(&mut self.cache.borrow_mut());

        self.cache.borrow_mut().set_sync_root(Root {
            namespace,
            version,
            root_type: self.root_type,
            hash: new_hash,
        });

        Ok(new_hash)
    }
}

pub fn sub_multi_commit(ptr: NodePtrRef) -> Result<Hash> {
    let mut handles: Vec<thread::JoinHandle<()>> = vec![];

    let _ = _dispatch_commit(ptr.clone(), 0, 0, &mut |ptr, _index| {

        let tp = ThreadParam {
            ptr,
            sub_thread: false,
        };

        let handle = thread::spawn(move || {
            let ptr: NodePtrRef = tp.ptr;
            let _ = _multi_commit(ptr);
        });

        handles.push(handle);
    });

    while handles.len() > 0 {
        let _ = handles.remove(0).join();
    }

    let new_hash = _multi_commit(ptr.clone())?;

    Ok(new_hash)
}

pub fn _dispatch_commit<F>(ptr: NodePtrRef, depth: Depth, index: usize, run_thread: &mut F) -> Result<()>
where
    F: FnMut(NodePtrRef, usize) -> (),
{
    if ptr.borrow().clean {
        return Ok(());
    }

    match classify_noderef!(? ptr.borrow().node) {
        NodeKind::None => {
        }
        NodeKind::Internal => {
            let some_node_ref = ptr.borrow().get_node();
            if !some_node_ref.borrow().is_clean() {
                let int_left = noderef_as!(some_node_ref, Internal).left.clone();
                let int_right = noderef_as!(some_node_ref, Internal).right.clone();

                if depth == THREAD_DEPTHS-1 {
                    run_thread(int_left, index*2);
                    run_thread(int_right, index*2+1);
                } else {
                    _dispatch_commit(int_left, depth+1, index*2, run_thread)?;
                    _dispatch_commit(int_right, depth+1, index*2+1, run_thread)?;
                }
            }
        }
        NodeKind::Leaf => {
        }
    };

    Ok(())
}

pub fn _multi_commit(ptr: NodePtrRef) -> Result<Hash> {
    if ptr.borrow().clean {
        return Ok(ptr.borrow().hash);
    }

    match classify_noderef!(? ptr.borrow().node) {
        NodeKind::None => {
            ptr.borrow_mut().hash = Hash::empty_hash();
        }
        NodeKind::Internal => {
            let some_node_ref = ptr.borrow().get_node();
            if some_node_ref.borrow().is_clean() {
                ptr.borrow_mut().hash = some_node_ref.borrow().get_hash();
            } else {
                let int_leaf_node = noderef_as!(some_node_ref, Internal).leaf_node.clone();
                let int_left = noderef_as!(some_node_ref, Internal).left.clone();
                let int_right = noderef_as!(some_node_ref, Internal).right.clone();

                _multi_commit(int_leaf_node)?;
                _multi_commit(int_left)?;
                _multi_commit(int_right)?;

                some_node_ref.borrow_mut().update_hash();
                ptr.borrow_mut().hash = some_node_ref.borrow().get_hash();

                noderef_as_mut!(some_node_ref, Internal).clean = true;
            }
        }
        NodeKind::Leaf => {
            let node_ref = ptr.borrow().get_node();
            if node_ref.borrow().is_clean() {
                ptr.borrow_mut().hash = node_ref.borrow().get_hash();
            } else {
                node_ref.borrow_mut().update_hash();
                ptr.borrow_mut().hash = node_ref.borrow().get_hash();

                noderef_as_mut!(node_ref, Leaf).clean = true;
            }
        }
    };

    ptr.clone().borrow_mut().clean = true;

    Ok(ptr.borrow().hash)
}

pub fn _commit<C: Cache>(ptr: NodePtrRef, update_list: &mut UpdateList<C>) -> Result<Hash> {
    if ptr.borrow().clean {
        return Ok(ptr.borrow().hash);
    }

    match classify_noderef!(? ptr.borrow().node) {
        NodeKind::None => {
            ptr.borrow_mut().hash = Hash::empty_hash();
        }
        NodeKind::Internal => {
            let some_node_ref = ptr.borrow().get_node();
            if some_node_ref.borrow().is_clean() {
                ptr.borrow_mut().hash = some_node_ref.borrow().get_hash();
            } else {
                let int_leaf_node = noderef_as!(some_node_ref, Internal).leaf_node.clone();
                let int_left = noderef_as!(some_node_ref, Internal).left.clone();
                let int_right = noderef_as!(some_node_ref, Internal).right.clone();

                _commit(int_leaf_node, update_list)?;
                _commit(int_left, update_list)?;
                _commit(int_right, update_list)?;

                some_node_ref.borrow_mut().update_hash();
                ptr.borrow_mut().hash = some_node_ref.borrow().get_hash();

                update_list.push(Box::new(move |_| {
                    noderef_as_mut!(some_node_ref, Internal).clean = true
                }));
            }
        }
        NodeKind::Leaf => {
            let node_ref = ptr.borrow().get_node();
            if node_ref.borrow().is_clean() {
                ptr.borrow_mut().hash = node_ref.borrow().get_hash();
            } else {
                node_ref.borrow_mut().update_hash();
                ptr.borrow_mut().hash = node_ref.borrow().get_hash();

                update_list.push(Box::new(move |_| {
                    noderef_as_mut!(node_ref, Leaf).clean = true
                }));
            }
        }
    };

    let closure_ptr = ptr.clone();
    update_list.push(Box::new(move |cache| {
        closure_ptr.borrow_mut().clean = true;
        // Make node eligible for eviction.
        cache.commit_node(closure_ptr.clone());
    }));

    Ok(ptr.borrow().hash)
}
