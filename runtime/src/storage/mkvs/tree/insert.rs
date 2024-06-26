use std::{mem, sync::Arc, collections::BTreeMap, thread};
use std::time::Duration;
use slog::info;

use anyhow::{anyhow, Result};
use io_context::Context;

use crate::storage::mkvs::{cache::*, tree::*};
use crate::common::logger::get_logger;

use super::lookup::FetcherSyncGet;

#[derive(Debug, Default)]
struct ThreadParam {
    node: Option<NodeRef>,
    ptr: Option<NodePtrRef>,
    bit_depth: Depth, 
    depth: Depth,   //new inserted node location
    index: usize,   // or thread head node location
    new_dep: Depth, //new location after
    new_idx: usize, // existing node push down
    kvs: Option<Vec<(Vec<u8>, Vec<u8>)>>,
}

unsafe impl Send for ThreadParam {}

const THREAD_DEPTHS: u16 = 3;

fn get_sub_threads(depth: Depth, index: usize) -> Vec<usize> {
    if depth == THREAD_DEPTHS {
        return vec![index];
    }
    let mut left = get_sub_threads(depth+1, index*2);
    let mut right = get_sub_threads(depth+1, index*2+1);
    let _ = left.append(&mut right);
    left
}

fn new_internal_node_ptr(node: Option<NodeRef>) -> NodePtrRef {
    Rc::new(RefCell::new(NodePointer {
        node,
        ..Default::default()
    }))
}

fn new_internal_node(
    label: &Key,
    label_bit_length: Depth,
    leaf_node: NodePtrRef,
    left: NodePtrRef,
    right: NodePtrRef,
) -> NodePtrRef {
    let node = Rc::new(RefCell::new(NodeBox::Internal(InternalNode {
        label: label.clone(),
        label_bit_length,
        leaf_node,
        left,
        right,
        ..Default::default()
    })));
    new_internal_node_ptr(Some(node))
}

fn new_leaf_node_ptr(node: Option<NodeRef>) -> NodePtrRef {
    Rc::new(RefCell::new(NodePointer {
        node,
        ..Default::default()
    }))
}

fn new_leaf_node(key: &Key, value: Value) -> NodePtrRef {
    let node = Rc::new(RefCell::new(NodeBox::Leaf(LeafNode {
        key: key.clone(),
        value,
        ..Default::default()
    })));
    new_leaf_node_ptr(Some(node))
}

fn _add(
    ctx: &Arc<Context>,
    ptr: NodePtrRef,
    bit_depth: Depth,
    key: &Key,
    val: Value,
) -> Result<(NodePtrRef, Option<Value>)> {
    //{{{
    let node_ref = ptr.borrow().node.clone();

    let (_, key_remainder) = key.split(bit_depth, key.bit_length());

    match classify_noderef!(?node_ref) {
        NodeKind::None => {
            return Ok((new_leaf_node(key, val), None));
        }
        NodeKind::Internal => {
            let node_ref = node_ref.unwrap();
            let (leaf_node, left, right): (NodePtrRef, NodePtrRef, NodePtrRef);
            let cp_len: Depth;
            let label_prefix: Key;
            if let NodeBox::Internal(ref mut n) = *node_ref.borrow_mut() {
                cp_len = n.label.common_prefix_len(
                    n.label_bit_length,
                    &key_remainder,
                    key.bit_length() - bit_depth,
                );

                if cp_len == n.label_bit_length {
                    // The current part of key matched the node's Label. Do recursion.
                    let r: (NodePtrRef, Option<Value>);
                    if key.bit_length() == bit_depth + n.label_bit_length {
                        // Key to insert ends exactly at this node. Add it to the
                        // existing internal node as LeafNode.
                        r = _add(
                            ctx,
                            n.leaf_node.clone(),
                            bit_depth + n.label_bit_length,
                            key,
                            val,
                        )?;
                        n.leaf_node = r.0;
                    } else if key.get_bit(bit_depth + n.label_bit_length) {
                        // Insert recursively based on the bit value.
                        r = _add(
                            ctx,
                            n.right.clone(),
                            bit_depth + n.label_bit_length,
                            key,
                            val,
                        )?;
                        n.right = r.0;
                    } else {
                        r = _add(
                            ctx,
                            n.left.clone(),
                            bit_depth + n.label_bit_length,
                            key,
                            val,
                        )?;
                        n.left = r.0;
                    }

                    if !n.leaf_node.borrow().clean
                        || !n.left.borrow().clean
                        || !n.right.borrow().clean
                    {
                        n.clean = false;
                        ptr.borrow_mut().clean = false;
                    }

                    return Ok((ptr, r.1));
                }

                // Key mismatches the label at position cp_len. Split the edge and
                // insert new leaf.
                let label_split = n.label.split(cp_len, n.label_bit_length);
                label_prefix = label_split.0;
                n.label = label_split.1;
                n.label_bit_length -= cp_len;
                n.clean = false;
                ptr.borrow_mut().clean = false;

                let new_leaf = new_leaf_node(key, val);
                if key.bit_length() - bit_depth == cp_len {
                    // The key is a prefix of existing path.
                    leaf_node = new_leaf;
                    if n.label.get_bit(0) {
                        left = NodePointer::null_ptr();
                        right = ptr;
                    } else {
                        left = ptr;
                        right = NodePointer::null_ptr();
                    }
                } else {
                    leaf_node = NodePointer::null_ptr();
                    if key_remainder.get_bit(cp_len) {
                        left = ptr;
                        right = new_leaf;
                    } else {
                        left = new_leaf;
                        right = ptr;
                    }
                }
            } else {
                return Err(anyhow!(
                    "insert.rs: unknown internal node_ref {:?}",
                    node_ref
                ));
            }

            return Ok((
                new_internal_node(
                    &label_prefix,
                    cp_len,
                    leaf_node,
                    left,
                    right,
                ),
                None,
            ));
        }
        NodeKind::Leaf => {
            // If the key matches, we can just update the value.
            let node_ref = node_ref.unwrap();
            let (leaf_node, left, right): (NodePtrRef, NodePtrRef, NodePtrRef);
            let cp_len: Depth;
            let label_prefix: Key;
            if let NodeBox::Leaf(ref mut n) = *node_ref.borrow_mut() {
                // Should always succeed.
                if n.key == *key {
                    // If the key matches, we can just update the value.
                    if n.value == val {
                        return Ok((ptr, Some(val)));
                    }
                    let old_val = mem::replace(&mut n.value, val);
                    n.clean = false;
                    ptr.borrow_mut().clean = false;
                    return Ok((ptr, Some(old_val)));
                }

                let (_, leaf_key_remainder) = n.key.split(bit_depth, n.key.bit_length());
                cp_len = leaf_key_remainder.common_prefix_len(
                    n.key.bit_length() - bit_depth,
                    &key_remainder,
                    key.bit_length() - bit_depth,
                );

                // Key mismatches the label at position cp_len. Split the edge.
                label_prefix = leaf_key_remainder
                    .split(cp_len, leaf_key_remainder.bit_length())
                    .0;
                let new_leaf = new_leaf_node(key, val);

                if key.bit_length() - bit_depth == cp_len {
                    // Inserted key is a prefix of the label.
                    leaf_node = new_leaf;
                    if leaf_key_remainder.get_bit(cp_len) {
                        left = NodePointer::null_ptr();
                        right = ptr;
                    } else {
                        left = ptr;
                        right = NodePointer::null_ptr();
                    }
                } else if n.key.bit_length() - bit_depth == cp_len {
                    // Label is a prefix of the inserted key.
                    leaf_node = ptr;
                    if key_remainder.get_bit(cp_len) {
                        left = NodePointer::null_ptr();
                        right = new_leaf;
                    } else {
                        left = new_leaf;
                        right = NodePointer::null_ptr();
                    }
                } else {
                    leaf_node = NodePointer::null_ptr();
                    if key_remainder.get_bit(cp_len) {
                        left = ptr;
                        right = new_leaf;
                    } else {
                        left = new_leaf;
                        right = ptr;
                    }
                }
            } else {
                return Err(anyhow!("insert.rs: invalid leaf node_ref {:?}", node_ref));
            }

            let new_internal = new_internal_node(
                &label_prefix,
                cp_len,
                leaf_node,
                left,
                right,
            );
            Ok((new_internal, None))
        }
    }
    //}}}
}

fn _dispatch_insert(
    ctx: &Arc<Context>,
    ptr: NodePtrRef,
    bit_depth: Depth,
    depth: Depth,
    index: usize,
    key: &Key,
    val: Value,
) -> Result<(NodePtrRef, Option<ThreadParam>)> {
    //{{{
    let node_ref = ptr.borrow().node.clone();

    let (_, key_remainder) = key.split(bit_depth, key.bit_length());

    match classify_noderef!(?node_ref) {
        NodeKind::None => {
            Ok((
                new_leaf_node(key, val),
                None
            ))
        },
        NodeKind::Internal => {
            let node_ref = node_ref.unwrap();
            let node = node_ref.clone();
            let (leaf_node, left, right): (NodePtrRef, NodePtrRef, NodePtrRef);
            let cp_len: Depth;
            let label_prefix: Key;
            let th_act: Option<ThreadParam>;
            if let NodeBox::Internal(ref mut n) = *node_ref.borrow_mut() {
                cp_len = n.label.common_prefix_len(
                    n.label_bit_length,
                    &key_remainder,
                    key.bit_length() - bit_depth,
                );

                if cp_len == n.label_bit_length {
                    //{{{
                    // The current part of key matched the node's Label. Do recursion.
                    let r: (NodePtrRef, Option<ThreadParam>);
                    let mut by_th = false;
                    if key.bit_length() == bit_depth + n.label_bit_length {
                        // Key to insert ends exactly at this node. Add it to the
                        // existing internal node as LeafNode.
                        r = _dispatch_insert(
                            ctx,
                            n.leaf_node.clone(),
                            bit_depth + n.label_bit_length,
                            depth,
                            index,
                            key,
                            val,
                        )?;
                        n.leaf_node = r.0;
                        th_act = r.1;
                    } else if key.get_bit(bit_depth + n.label_bit_length) {
                        if depth == THREAD_DEPTHS-1 {
                            th_act = Some(ThreadParam {
                                node: Some(node),
                                bit_depth: bit_depth + n.label_bit_length,
                                depth: depth+1,
                                index: index*2+1,
                                ..Default::default()
                            });
                            by_th = true;
                        } else {
                            // Insert recursively based on the bit value.
                            r = _dispatch_insert(
                                ctx,
                                n.right.clone(),
                                bit_depth + n.label_bit_length,
                                depth+1,
                                index*2+1,
                                key,
                                val,
                            )?;
                            n.right = r.0;
                            th_act = r.1;
                        }
                    } else {
                        if depth == THREAD_DEPTHS-1 {
                            th_act = Some(ThreadParam {
                                node: Some(node),
                                bit_depth: bit_depth + n.label_bit_length,
                                depth: depth+1,
                                index: index*2,
                                ..Default::default()
                            });
                            by_th = true;
                        } else {
                            r = _dispatch_insert(
                                ctx,
                                n.left.clone(),
                                bit_depth + n.label_bit_length,
                                depth+1,
                                index*2,
                                key,
                                val,
                            )?;
                            n.left = r.0;
                            th_act = r.1;
                        }
                    }

                    if by_th 
                        || !n.leaf_node.borrow().clean
                        || !n.left.borrow().clean
                        || !n.right.borrow().clean
                    {
                        n.clean = false;
                        ptr.borrow_mut().clean = false;
                        // No longer eligible for eviction as it is dirty.
                    }

                    return Ok((ptr, th_act));
                    //}}}
                }

                // Key mismatches the label at position cp_len. Split the edge and
                // insert new leaf.
                let label_split = n.label.split(cp_len, n.label_bit_length);
                label_prefix = label_split.0;
                n.label = label_split.1;
                n.label_bit_length -= cp_len;
                n.clean = false;
                ptr.borrow_mut().clean = false;
                // No longer eligible for eviction as it is dirty.

                let new_leaf = new_leaf_node(key, val);
                let new_dep: Depth = depth + 1;
                let new_idx: usize;

                if key.bit_length() - bit_depth == cp_len {
                    // The key is a prefix of existing path.
                    leaf_node = new_leaf;
                    if n.label.get_bit(0) {
                        left = NodePointer::null_ptr();
                        right = ptr;
                        new_idx = index*2+1;
                    } else {
                        left = ptr;
                        right = NodePointer::null_ptr();
                        new_idx = index*2;
                    }
                } else {
                    leaf_node = NodePointer::null_ptr();
                    if key_remainder.get_bit(cp_len) {
                        left = ptr;
                        right = new_leaf;
                        new_idx = index*2;
                    } else {
                        left = new_leaf;
                        right = ptr;
                        new_idx = index*2+1;
                    }
                }

                th_act = Some(ThreadParam {
                    bit_depth, 
                    depth,
                    index,
                    new_dep,
                    new_idx,
                    ..Default::default()
                });

            } else {
                return Err(anyhow!(
                    "insert.rs: unknown internal node_ref {:?}",
                    node_ref
                ));
            }

            Ok((new_internal_node(
                    &label_prefix,
                    cp_len,
                    leaf_node,
                    left,
                    right,
                ),
                th_act
            ))
        },
        NodeKind::Leaf => {
            // If the key matches, we can just update the value.
            let node_ref = node_ref.unwrap();
            let (leaf_node, left, right): (NodePtrRef, NodePtrRef, NodePtrRef);
            let cp_len: Depth;
            let label_prefix: Key;
            if let NodeBox::Leaf(ref mut n) = *node_ref.borrow_mut() {
                // Should always succeed.
                if n.key == *key {
                    // If the key matches, we can just update the value.
                    if n.value == val {
                        return Ok((ptr, None));
                    }
                    let _val = mem::replace(&mut n.value, val);
                    n.clean = false;
                    ptr.borrow_mut().clean = false;
                    // No longer eligible for eviction as it is dirty.
                    return Ok((ptr, None));
                }

                let (_, leaf_key_remainder) = n.key.split(bit_depth, n.key.bit_length());
                cp_len = leaf_key_remainder.common_prefix_len(
                    n.key.bit_length() - bit_depth,
                    &key_remainder,
                    key.bit_length() - bit_depth,
                );

                // Key mismatches the label at position cp_len. Split the edge.
                label_prefix = leaf_key_remainder
                    .split(cp_len, leaf_key_remainder.bit_length())
                    .0;
                let new_leaf = new_leaf_node(key, val);

                if key.bit_length() - bit_depth == cp_len {
                    // Inserted key is a prefix of the label.
                    leaf_node = new_leaf;
                    if leaf_key_remainder.get_bit(cp_len) {
                        left = NodePointer::null_ptr();
                        right = ptr;
                    } else {
                        left = ptr;
                        right = NodePointer::null_ptr();
                    }
                } else if n.key.bit_length() - bit_depth == cp_len {
                    // Label is a prefix of the inserted key.
                    leaf_node = ptr;
                    if key_remainder.get_bit(cp_len) {
                        left = NodePointer::null_ptr();
                        right = new_leaf;
                    } else {
                        left = new_leaf;
                        right = NodePointer::null_ptr();
                    }
                } else {
                    leaf_node = NodePointer::null_ptr();
                    if key_remainder.get_bit(cp_len) {
                        left = ptr;
                        right = new_leaf;
                    } else {
                        left = new_leaf;
                        right = ptr;
                    }
                }
            } else {
                return Err(anyhow!("insert.rs: invalid leaf node_ref {:?}", node_ref));
            }

            Ok((new_internal_node(
                    &label_prefix,
                    cp_len,
                    leaf_node,
                    left,
                    right,
                ),
                None
            ))
        }
    }
    //}}}
}


pub fn sub_multi_insert(ctx: Context, kvs: Vec<(Vec<u8>, Vec<u8>)>, ptr: NodePtrRef, bit_depth: Depth) -> Result<NodePtrRef>
{
    let ctx = ctx.freeze();

    let mut ptr = ptr;
    let num_ths = 1<<THREAD_DEPTHS;
    let mut thread_bits = 0;
    let mut handles: Vec<thread::JoinHandle<Vec<ThreadParam>>> = vec![];
    let mut th_params: Vec<Option<Vec<ThreadParam>>> = vec![];
    let mut num_kvs: Vec<usize> = vec![];
    for _ in 0..num_ths {
        th_params.push(None);
        num_kvs.push(0);
    }

    for (key, val) in &kvs {
        //{{{
        let ptr_ref = ptr.clone();
        let r = _dispatch_insert(&ctx, ptr_ref, bit_depth, 0, 0, &key, val.clone());
        if !r.is_ok() {
            continue;
        }

        let r = r.unwrap();

        ptr = r.0;

        let p = r.1;
        if !p.is_some() {
            continue;
        }

        let mut p = p.unwrap();

        if p.depth < THREAD_DEPTHS {
            //change threads to new nodes due to push down
            let idxes = get_sub_threads(p.depth, p.index);
            let new_idxes = get_sub_threads(p.new_dep, p.new_idx);

            let mut tmp: Vec<Option<Vec<ThreadParam>>> = vec![];
            for _ in 0..new_idxes.len() {
                tmp.push(None);
            }
            for i in 0..idxes.len() {
                let idx = idxes[i];
                if (thread_bits & (1<<idx)) != 0 && idx != new_idxes[i>>1] {
                    if tmp[i>>1].is_some() {
                        tmp[i>>1].as_mut().unwrap().append(&mut th_params[idx].take().unwrap());
                    } else {
                        tmp[i>>1].replace(th_params[idx].take().unwrap());
                    }
                    thread_bits &= !(1<<idx);
                }
            }
            for i in 0..new_idxes.len() {
                if tmp[i].is_some() {
                    let idx = new_idxes[i];
                    if (thread_bits & (1<<idx)) != 0 {
                        th_params[idx].as_mut().unwrap().append(&mut tmp[i].take().unwrap());
                    } else {
                        th_params[idx].replace(tmp[i].take().unwrap());
                        thread_bits |= 1<<idx;
                    }
                }
            }
        } else if p.depth == THREAD_DEPTHS {
            //for thread to insert
            let index = p.index;

            if (thread_bits & (1<<index)) == 0 {
                thread_bits |= 1<<index;

                p.kvs.replace(vec![]);
                if th_params[index].is_none() {
                    th_params[index].replace(vec![]);
                }
                th_params[index].as_mut().unwrap().push(p);
            }

            let params = th_params[index].as_mut().unwrap();
            let last = params.last_mut().unwrap();

            last.kvs.as_mut().unwrap().push((key.clone(), val.clone()));
        }
        //}}}
    }

    for i in 0..num_ths {
        if th_params[i].is_some() {
            num_kvs[i] = th_params[i].as_ref().unwrap().iter().fold(0, |acc, x| acc + x.kvs.as_ref().unwrap().len());
        }
    }

    for i in 0..num_ths {
        //{{{
        let idx = i;
        if th_params[idx].is_none() {
            continue;
        }

        let mut params = th_params[idx].take().unwrap();

        let ctx = Context::create_child(&ctx).freeze();
        //let total_kvs = kvs.len();

        let handle = thread::spawn(move || {
            //{{{
            for i in 0..params.len() {
                let param = &mut params[i];
                let mut node_ptr = if (param.index & 1) == 0 {
                    noderef_as!(param.node.as_ref().unwrap(), Internal).left.clone()
                } else {
                    noderef_as!(param.node.as_ref().unwrap(), Internal).right.clone()
                };

                let mut param_kvs = param.kvs.take().unwrap();

                while param_kvs.len() > 0 {
                    let kv = param_kvs.pop().unwrap();
                    let r = _add(&ctx, node_ptr.clone(), param.bit_depth, &kv.0, kv.1);
                    if r.is_ok() {
                        let (new_root, _) = r.unwrap();
                        node_ptr = new_root;
                    }
                }

                param.ptr.replace(node_ptr);
            }

            params
            //}}}
        });

        handles.push(handle);
        //}}}
    }

    let mut all_params: Vec<ThreadParam> = vec![];
    while handles.len() > 0 {
        let handle = handles.remove(0);
        let mut params = handle.join().unwrap();
        all_params.append(&mut params);
    }
    for mut param in all_params {
        let mut tries = 0;
        let mut node = loop {
            let x = param.node.as_mut().unwrap().try_borrow_mut();
            if x.is_ok() {
                break x.unwrap();
            }
            tries += 1;
            if (tries % 100000) == 0 {
                info!(get_logger("mkvs/insert"), "_sub_multi_insert try_borrow_mut...";
                    "tries" => tries,
                );
            }
            thread::sleep(Duration::from_micros(10));
        };
        if tries > 0 {
            info!(get_logger("mkvs/insert"), "_sub_multi_insert try_borrow_mut";
                "tries" => tries,
            );
        }

        let inter = match *node {
            NodeBox::Internal(ref mut deref) => deref,
            _ => unreachable!(),
        };

        if (param.index & 1) == 0 {
            inter.left = param.ptr.take().unwrap();
        } else {
            inter.right = param.ptr.take().unwrap();
        }
    }

    Ok(ptr)
}

impl Tree {
    /// Insert a key/value pair into the tree.
    pub fn insert(&mut self, ctx: Context, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        let ctx = ctx.freeze();
        let pending_root = self.cache.borrow().get_pending_root();
        let boxed_key = key.to_vec();
        let boxed_val = value.to_vec();

        // Remember where the path from root to target node ends (will end).
        self.cache.borrow_mut().mark_position();

        let (new_root, old_val) = self._insert(&ctx, pending_root, 0, &boxed_key, boxed_val)?;
        self.cache.borrow_mut().set_pending_root(new_root);

        Ok(old_val)
    }

    pub fn multi_insert<F>(&mut self, ctx: Context, kvs: &BTreeMap<Vec<u8>, Vec<u8>>, mut cb: F) -> Result<Vec<usize>>
    where
        F: FnMut (&Vec<u8>, &Vec<u8>) -> (),
    {
        let ctx = ctx.freeze();

        let num_ths = 1<<THREAD_DEPTHS;
        let mut thread_bits = 0;
        let mut handles: Vec<thread::JoinHandle<Vec<ThreadParam>>> = vec![];
        let mut th_params: Vec<Option<Vec<ThreadParam>>> = vec![];
        let mut num_kvs: Vec<usize> = vec![];
        let mut sort_idx: Vec<usize> = vec![];
        for i in 0..num_ths {
            th_params.push(None);
            num_kvs.push(0);
            sort_idx.push(i);
        }


        for (key, val) in kvs {
            //{{{
            let pending_root = self.cache.borrow().get_pending_root();

            let r = _dispatch_insert(&ctx, pending_root, 0, 0, 0, &key, val.clone());
            if !r.is_ok() {
                continue;
            }

            let r = r.unwrap();

            self.cache.borrow_mut().set_pending_root(r.0);

            cb(&key, &val);

            let p = r.1;
            if !p.is_some() {
                continue;
            }

            let mut p = p.unwrap();

            if p.depth < THREAD_DEPTHS {
                //change threads to new nodes due to push down
                let idxes = get_sub_threads(p.depth, p.index);
                let new_idxes = get_sub_threads(p.new_dep, p.new_idx);

                let mut tmp: Vec<Option<Vec<ThreadParam>>> = vec![];
                for _ in 0..new_idxes.len() {
                    tmp.push(None);
                }
                for i in 0..idxes.len() {
                    let idx = idxes[i];
                    if (thread_bits & (1<<idx)) != 0 && idx != new_idxes[i>>1] {
                        if tmp[i>>1].is_some() {
                            tmp[i>>1].as_mut().unwrap().append(&mut th_params[idx].take().unwrap());
                        } else {
                            tmp[i>>1].replace(th_params[idx].take().unwrap());
                        }
                        thread_bits &= !(1<<idx);
                    }
                }
                for i in 0..new_idxes.len() {
                    if tmp[i].is_some() {
                        let idx = new_idxes[i];
                        if (thread_bits & (1<<idx)) != 0 {
                            th_params[idx].as_mut().unwrap().append(&mut tmp[i].take().unwrap());
                        } else {
                            th_params[idx].replace(tmp[i].take().unwrap());
                            thread_bits |= 1<<idx;
                        }
                    }
                }
            } else if p.depth == THREAD_DEPTHS {
                //for thread to insert
                let index = p.index;

                if (thread_bits & (1<<index)) == 0 {
                    thread_bits |= 1<<index;

                    p.kvs.replace(vec![]);
                    if th_params[index].is_none() {
                        th_params[index].replace(vec![]);
                    }
                    th_params[index].as_mut().unwrap().push(p);
                }

                let params = th_params[index].as_mut().unwrap();
                let last = params.last_mut().unwrap();

                last.kvs.as_mut().unwrap().push((key.clone(), val.clone()));
            }
            //}}}
        }

        for i in 0..num_ths {
            if th_params[i].is_some() {
                num_kvs[i] = th_params[i].as_ref().unwrap().iter().fold(0, |acc, x| acc + x.kvs.as_ref().unwrap().len());
            }
        }

        sort_idx.sort_by(|a, b| num_kvs[*a].cmp(&num_kvs[*b]));

        let mut sub_params: Vec<ThreadParam> = vec![];
        let mut sub_total = 0;

        for i in 0..num_ths {
            //{{{
            let idx = sort_idx[i];
            if th_params[idx].is_none() {
                continue;
            }

            let mut params = th_params[idx].take().unwrap();

            if num_kvs[idx] < kvs.len() / num_ths || i == (num_ths-1) {
                sub_total += num_kvs[idx];
                sub_params.append(&mut params);
                if sub_total > kvs.len() / num_ths || i == (num_ths-1) {
                    params = sub_params;
                    sub_params = vec![];
                    sub_total = 0;
                } else {
                    continue;
                }
            }

            let ctx = Context::create_child(&ctx).freeze();
            let total_kvs = kvs.len();

            
            let handle = thread::spawn(move || {
                //{{{
                for i in 0..params.len() {
                    let param = &mut params[i];
                    let mut node_ptr = if (param.index & 1) == 0 {
                        noderef_as!(param.node.as_ref().unwrap(), Internal).left.clone()
                    } else {
                        noderef_as!(param.node.as_ref().unwrap(), Internal).right.clone()
                    };

                    let mut param_kvs = param.kvs.take().unwrap();

                    if param_kvs.len() > total_kvs/2 && param_kvs.len() >= 500 {
                        let r = sub_multi_insert(
                            Context::create_child(&ctx), param_kvs, node_ptr.clone(), param.bit_depth
                        );
                        if r.is_ok() {
                            node_ptr = r.unwrap();
                        }
                    } else {
                        while param_kvs.len() > 0 {
                            let kv = param_kvs.pop().unwrap();
                            let r = _add(&ctx, node_ptr.clone(), param.bit_depth, &kv.0, kv.1);
                            if r.is_ok() {
                                let (new_root, _) = r.unwrap();
                                node_ptr = new_root;
                            }
                        }
                    }

                    param.ptr.replace(node_ptr);
                }

                params
                //}}}
            });

            handles.push(handle);
            //}}}
        }

        let mut all_params: Vec<ThreadParam> = vec![];
        while handles.len() > 0 {
            let handle = handles.remove(0);
            let mut params = handle.join().unwrap();
            all_params.append(&mut params);
        }
        for mut param in all_params {
            let mut tries = 0;
            let mut node = loop {
                let x = param.node.as_mut().unwrap().try_borrow_mut();
                if x.is_ok() {
                    break x.unwrap();
                }
                tries += 1;
                if (tries % 100000) == 0 {
                    info!(get_logger("mkvs/insert"), "_sub_multi_insert try_borrow_mut...";
                        "tries" => tries,
                    );
                }
                thread::sleep(Duration::from_micros(10));
            };
            if tries > 0 {
                info!(get_logger("mkvs/insert"), "_multi_insert try_borrow_mut";
                    "tries" => tries,
                );
            }

            let inter = match *node {
                NodeBox::Internal(ref mut deref) => deref,
                _ => unreachable!(),
            };

            if (param.index & 1) == 0 {
                inter.left = param.ptr.take().unwrap();
            } else {
                inter.right = param.ptr.take().unwrap();
            }
        }

        Ok(num_kvs)
    }


    fn _insert(
        &mut self,
        ctx: &Arc<Context>,
        ptr: NodePtrRef,
        bit_depth: Depth,
        key: &Key,
        val: Value,
    ) -> Result<(NodePtrRef, Option<Value>)> {
        let node_ref = self.cache.borrow_mut().deref_node_ptr(
            ctx,
            ptr.clone(),
            Some(FetcherSyncGet::new(key, false)),
        )?;

        let (_, key_remainder) = key.split(bit_depth, key.bit_length());

        match classify_noderef!(?node_ref) {
            NodeKind::None => {
                return Ok((self.cache.borrow_mut().new_leaf_node(key, val), None));
            }
            NodeKind::Internal => {
                let node_ref = node_ref.unwrap();
                let (leaf_node, left, right): (NodePtrRef, NodePtrRef, NodePtrRef);
                let cp_len: Depth;
                let label_prefix: Key;
                if let NodeBox::Internal(ref mut n) = *node_ref.borrow_mut() {
                    cp_len = n.label.common_prefix_len(
                        n.label_bit_length,
                        &key_remainder,
                        key.bit_length() - bit_depth,
                    );

                    if cp_len == n.label_bit_length {
                        // The current part of key matched the node's Label. Do recursion.
                        let r: (NodePtrRef, Option<Value>);
                        if key.bit_length() == bit_depth + n.label_bit_length {
                            // Key to insert ends exactly at this node. Add it to the
                            // existing internal node as LeafNode.
                            r = self._insert(
                                ctx,
                                n.leaf_node.clone(),
                                bit_depth + n.label_bit_length,
                                key,
                                val,
                            )?;
                            n.leaf_node = r.0;
                        } else if key.get_bit(bit_depth + n.label_bit_length) {
                            // Insert recursively based on the bit value.
                            r = self._insert(
                                ctx,
                                n.right.clone(),
                                bit_depth + n.label_bit_length,
                                key,
                                val,
                            )?;
                            n.right = r.0;
                        } else {
                            r = self._insert(
                                ctx,
                                n.left.clone(),
                                bit_depth + n.label_bit_length,
                                key,
                                val,
                            )?;
                            n.left = r.0;
                        }

                        if !n.leaf_node.borrow().clean
                            || !n.left.borrow().clean
                            || !n.right.borrow().clean
                        {
                            n.clean = false;
                            ptr.borrow_mut().clean = false;
                            // No longer eligible for eviction as it is dirty.
                            self.cache
                                .borrow_mut()
                                .rollback_node(ptr.clone(), NodeKind::Internal);
                        }

                        return Ok((ptr, r.1));
                    }

                    // Key mismatches the label at position cp_len. Split the edge and
                    // insert new leaf.
                    let label_split = n.label.split(cp_len, n.label_bit_length);
                    label_prefix = label_split.0;
                    n.label = label_split.1;
                    n.label_bit_length -= cp_len;
                    n.clean = false;
                    ptr.borrow_mut().clean = false;
                    // No longer eligible for eviction as it is dirty.
                    self.cache
                        .borrow_mut()
                        .rollback_node(ptr.clone(), NodeKind::Internal);

                    let new_leaf = self.cache.borrow_mut().new_leaf_node(key, val);
                    if key.bit_length() - bit_depth == cp_len {
                        // The key is a prefix of existing path.
                        leaf_node = new_leaf;
                        if n.label.get_bit(0) {
                            left = NodePointer::null_ptr();
                            right = ptr;
                        } else {
                            left = ptr;
                            right = NodePointer::null_ptr();
                        }
                    } else {
                        leaf_node = NodePointer::null_ptr();
                        if key_remainder.get_bit(cp_len) {
                            left = ptr;
                            right = new_leaf;
                        } else {
                            left = new_leaf;
                            right = ptr;
                        }
                    }
                } else {
                    return Err(anyhow!(
                        "insert.rs: unknown internal node_ref {:?}",
                        node_ref
                    ));
                }

                return Ok((
                    self.cache.borrow_mut().new_internal_node(
                        &label_prefix,
                        cp_len,
                        leaf_node,
                        left,
                        right,
                    ),
                    None,
                ));
            }
            NodeKind::Leaf => {
                // If the key matches, we can just update the value.
                let node_ref = node_ref.unwrap();
                let (leaf_node, left, right): (NodePtrRef, NodePtrRef, NodePtrRef);
                let cp_len: Depth;
                let label_prefix: Key;
                if let NodeBox::Leaf(ref mut n) = *node_ref.borrow_mut() {
                    // Should always succeed.
                    if n.key == *key {
                        // If the key matches, we can just update the value.
                        if n.value == val {
                            return Ok((ptr, Some(val)));
                        }
                        let old_val = mem::replace(&mut n.value, val);
                        n.clean = false;
                        ptr.borrow_mut().clean = false;
                        // No longer eligible for eviction as it is dirty.
                        self.cache
                            .borrow_mut()
                            .rollback_node(ptr.clone(), NodeKind::Leaf);
                        return Ok((ptr, Some(old_val)));
                    }

                    let (_, leaf_key_remainder) = n.key.split(bit_depth, n.key.bit_length());
                    cp_len = leaf_key_remainder.common_prefix_len(
                        n.key.bit_length() - bit_depth,
                        &key_remainder,
                        key.bit_length() - bit_depth,
                    );

                    // Key mismatches the label at position cp_len. Split the edge.
                    label_prefix = leaf_key_remainder
                        .split(cp_len, leaf_key_remainder.bit_length())
                        .0;
                    let new_leaf = self.cache.borrow_mut().new_leaf_node(key, val);

                    if key.bit_length() - bit_depth == cp_len {
                        // Inserted key is a prefix of the label.
                        leaf_node = new_leaf;
                        if leaf_key_remainder.get_bit(cp_len) {
                            left = NodePointer::null_ptr();
                            right = ptr;
                        } else {
                            left = ptr;
                            right = NodePointer::null_ptr();
                        }
                    } else if n.key.bit_length() - bit_depth == cp_len {
                        // Label is a prefix of the inserted key.
                        leaf_node = ptr;
                        if key_remainder.get_bit(cp_len) {
                            left = NodePointer::null_ptr();
                            right = new_leaf;
                        } else {
                            left = new_leaf;
                            right = NodePointer::null_ptr();
                        }
                    } else {
                        leaf_node = NodePointer::null_ptr();
                        if key_remainder.get_bit(cp_len) {
                            left = ptr;
                            right = new_leaf;
                        } else {
                            left = new_leaf;
                            right = ptr;
                        }
                    }
                } else {
                    return Err(anyhow!("insert.rs: invalid leaf node_ref {:?}", node_ref));
                }

                let new_internal = self.cache.borrow_mut().new_internal_node(
                    &label_prefix,
                    cp_len,
                    leaf_node,
                    left,
                    right,
                );
                Ok((new_internal, None))
            }
        }
    }
}
