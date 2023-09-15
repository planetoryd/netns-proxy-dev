#![feature(decl_macro)]
#![allow(unused)]
#![allow(non_snake_case)]
#![feature(hash_extract_if)]

use anyhow::{anyhow, bail, Ok, Result};
use bimap::BiMap;

use derivative::Derivative;
use fixedbitset::FixedBitSet;

use rustsat::{
    clause,
    encodings::{card, pb},
    instances::{BasicVarManager, ManageVars, Objective, SatInstance},
    types::Clause,
    types::{Lit, TernaryVal, Var},
};
use scuttle::{KernelFunctions, Limits, Options, PMinimal, Solve};
// use fixedbitset::FixedBitSet;
use std::{
    any::TypeId,
    collections::{hash_map::Entry, HashMap, HashSet},
    fmt::Debug,
    future::{self, Future},
    hash::Hash,
    ops::Index,
    pin::Pin,
};

use rustsat::instances::MultiOptInstance;

use daggy::{
    petgraph::{
        csr::Csr,
        graph::DefaultIx,
        visit::{
            EdgeRef, FilterNode, IntoEdges, IntoEdgesDirected, IntoNeighborsDirected,
            IntoNodeIdentifiers, NodeFiltered, NodeFilteredNodes, Reversed, Topo, VisitMap,
            Visitable,
        },
    },
    walker::{Filter, Peekable, Skip},
    Dag, NodeIndex, Walker,
};

pub trait Mergeable {
    fn merge(&mut self, Δ: Self) -> Result<()>;
}

/// Read or Write
pub enum ReqType {
    R,
    W,
}

pub type SATVar = usize;

#[derive(Hash, Debug, Clone, PartialEq, Eq)]
pub struct RsrcKey<K: Key>(pub TypeId, pub K);

pub trait Key: Hash + Eq + Debug + Clone {}

/// Subject key
pub trait SKey: Key {}

/// Task key, uniquely identifies a task within the scope of a subject
pub trait TKey: Key {}

pub struct FnPlan<'SharedState, SK: Key, TK: Key, K: Key, GS, E, S: Clone> {
    /// Identifies the subject it belongs to
    pub subject: SK,
    /// Set it to () if you don't need it.
    pub tkey: TK,
    /// Demands for resources
    pub req: HashMap<RsrcKey<K>, ReqType>,
    /// Option because we will move it out when executing
    pub exec: Option<
        Box<
            dyn FnOnce(&'SharedState GS) -> Pin<Box<dyn Future<Output = Result<E>> + 'SharedState>>
                + 'SharedState,
        >,
    >,
    /// State change that would be caused if the plan gets executed
    pub result: S,
}

impl<K: Key> Mergeable for HashMap<RsrcKey<K>, ReqType> {
    fn merge(&mut self, Δ: Self) -> Result<()> {
        for (k, v) in Δ {
            match self.entry(k) {
                Entry::Occupied(mut o) => {
                    o.get_mut().merge(v)?;
                }
                Entry::Vacant(va) => {
                    va.insert(v);
                }
            }
        }
        Ok(())
    }
}

impl Mergeable for ReqType {
    fn merge(&mut self, Δ: Self) -> Result<()> {
        match self {
            ReqType::R => *self = Δ,
            ReqType::W => (),
        }
        Ok(())
    }
}

pub type TaskKey = u8;

pub trait ScheSubject {
    /// Label-like small state
    type S: NodeStatusT;
    /// State changes a FnPlan can return. Effect
    type E;
    /// Global state, immutable
    type GS;
    /// Resource key
    type RKey: Key;
    /// Subject key
    type SK: SKey;
    /// Task key
    type TK: TKey;
    /// the task causes a status change
    fn next_task<'f>(
        &'f self,
        status: Self::S,
    ) -> Vec<FnPlan<'f, Self::SK, Self::TK, Self::RKey, Self::GS, Self::E, Self::S>>;
    fn subject_key(&self) -> &Self::SK;
    fn initial_status(&self) -> Self::S;
}

pub trait NodeStatusT: Clone {
    fn node_status(&self) -> NodeStatus;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeStatus {
    Done,
    Undone,
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct AsyncScheduler<'f,S: NodeStatusT, E, GS, RKey: Key, SK: SKey, TK: TKey> {
    /// Wait-for graph. A --depend---> B
    dag: Dag<Box<dyn ScheSubject<S = S, E = E, GS = GS, RKey = RKey, SK = SK, TK = TK>>, ()>,
    keys: BiMap<SK, NodeIndex>,
    state: HashMap<SK, S>,
    done: <Dag<Box<dyn ScheSubject<S = S, E = E, GS = GS, RKey = RKey, SK = SK, TK = TK>>, ()> as Visitable>::Map,
    plans: Vec<FnPlan<'f, SK, TK, RKey, GS, E, S>>,
    /// Runnable subjects freshly discoverd last iteration
    ready: HashSet<NodeIndex>,
    /// Nodes that are likely to be workable
    pending: HashSet<NodeIndex>
}

impl<'fp, S: NodeStatusT, E, GS, RKey: Key, SK: SKey, TK: TKey>
    AsyncScheduler<'fp, S, E, GS, RKey, SK, TK>
{
    pub async fn upkeep<'this: 'f, 'f>(
        &'this mut self,
        immutable: &'f GS,
    ) -> Result<Vec<(Result<E>, FnPlan<'f, SK, TK, RKey, GS, E, S>)>> {
        self.done.grow(self.dag.node_count());

        self.find_runnable_subjects();
        if self.ready.is_empty() {
            return Ok(vec![]);
        }

        let mut sat: SatInstance<BasicVarManager> = SatInstance::new();
        let mut tasks: HashMap<Var, FnPlan<SK, TK, RKey, GS, E, S>> = Default::default(); // whether enable a task
        let mut rsrcs: BiMap<Var, RsrcKey<RKey>> = Default::default(); // whether enable a resource
        let mut reads: BiMap<Var, RsrcKey<RKey>> = Default::default(); // whether read a resource
        let mut reader: HashMap<Var, Vec<Var>> = Default::default(); // Read_var to readers
        let mut writer: HashMap<Var, Vec<Var>> = Default::default(); // Resource to writers

        for sj in self.ready.iter().map(|x| &self.dag[*x]) {
            let fnplan = sj.next_task(
                self.state
                    .get(sj.subject_key())
                    .map(|k| k.to_owned())
                    .unwrap_or(sj.initial_status()),
            );
            for fp in fnplan {
                let tv = sat.var_manager().new_var();
                tasks.insert(tv, fp);
                let fp = tasks.get(&tv).unwrap();
                for (rs, access) in &fp.req {
                    if !rsrcs.contains_right(&rs) {
                        let rv = sat.var_manager().new_var();
                        rsrcs.insert(rv, rs.to_owned());
                        writer.insert(rv, vec![]);
                        let rv = sat.var_manager().new_var();
                        reads.insert(rv, rs.to_owned());
                        reader.insert(rv, vec![]);
                    }
                    let resv = rsrcs.get_by_right(&rs).unwrap();
                    let readv = reads.get_by_right(&rs).unwrap();
                    match access {
                        ReqType::R => {
                            reader.get_mut(readv).unwrap().push(tv);
                        }
                        ReqType::W => {
                            writer.get_mut(resv).unwrap().push(tv);
                        }
                    }
                }
            }
        }
        for (rv, readers) in reader {
            let rders: Vec<_> = readers.iter().map(|x| x.pos_lit()).collect();
            for tv in rders.iter() {
                // A reader enabled => Read
                sat.add_lit_impl_lit(*tv, rv.pos_lit());
            }
            // Read => One or more readers are enabled
            sat.add_lit_impl_clause(rv.pos_lit(), rders);
        }
        for (rv, writers) in writer {
            let mut users: Vec<_> = writers.iter().map(|x| x.pos_lit()).collect();
            let rskey = rsrcs.get_by_left(&rv).unwrap();
            let readv = reads.get_by_right(rskey).unwrap();
            users.push(readv.pos_lit());
            // Either Read, WriteA or WriteB
            impl_at_most_one(rv.pos_lit(), &users, &mut sat);
            // Read || WriteByA || WriteByB ==> ResourceEnabled
            sat.add_clause_impl_lit(users, rv.pos_lit());
        }

        let minimized = tasks.keys().map(|v| (v.neg_lit(), 1usize));
        let o: Objective = minimized.into_iter().collect();
        let mo = MultiOptInstance::compose(sat, vec![o]);
        let mut solver: PMinimal<
            pb::DefIncUpperBounding,
            card::DefIncUpperBounding,
            BasicVarManager,
            fn(rustsat::types::Assignment) -> Clause,
            rustsat_minisat::core::Minisat,
        > = PMinimal::new_defaults(mo, Options::default()).unwrap();
        solver.solve(Limits::none()).unwrap();

        let pareto_front = solver.pareto_front();
        let sol = pareto_front
            .into_iter()
            .next()
            .ok_or(AllocationError)?
            .into_iter()
            .next()
            .ok_or(AllocationError)?;

        let (exe, wait): (HashMap<_, _>, _) =
            tasks
                .into_iter()
                .partition(|(k, v)| match sol.var_value(*k) {
                    TernaryVal::True | TernaryVal::DontCare => true,
                    _ => false,
                });

        let k =
            futures::future::join_all(exe.into_iter().map(|(v, mut fp)| async move {
                ((fp.exec.take().unwrap())(immutable).await, fp)
            }))
            .await;

        for (r, fp) in &k {
            if r.is_ok() {
                self.done
                    .visit(*self.keys.get_by_left(&fp.subject).unwrap());
                self.state
                    .insert(fp.subject.to_owned(), fp.result.to_owned());
            }
        }

        Ok(k)
    }
    pub fn update(
        &mut self,
        subject: Box<dyn ScheSubject<S = S, TK = TK, E = E, GS = GS, RKey = RKey, SK = SK>>,
        deps: &[SK],
    ) -> Result<()> {
        let sk = subject.subject_key().to_owned();
        debug_assert!(subject.initial_status().node_status() == NodeStatus::Undone);
        if self.keys.contains_left(&sk) {
            bail!("repeated adding")
        }

        let ni = self.dag.add_node(subject);
        self.keys.insert(sk, ni);
        let mut pass = false;

        for k in deps.into_iter().map(|k| {
            self.keys.get_by_left(k).ok_or(anyhow!(
                "Trying to add a subject with non-existent dependency"
            ))
        }) {
            let dp = *k?;

            self.dag.add_edge(ni, dp, ())?;
            if !self.done[dp.index()] {
                pass = true;
            }
        }
        // at least one undone node ==> do not add to pending
        // In a static graph, all undone nodes can be visited from current pending nodes, by continue find_runnable
        // If I add any node to depend on them, it will be visited too.

        if !pass {
            self.pending.insert(ni);
        }

        Ok(())
    }
    pub fn find_runnable_subjects(&mut self) {
        // Traverse the source nodes
        // or traverse the pending
        let traverse: HashSet<NodeIndex> = if self.ready.is_empty() {
            NodeFiltered::from_fn(&self.dag, |ni| {
                // Parent --> Children/dependencies
                self.dag.children(ni).iter(&self.dag).next().is_none()
            })
            .node_identifiers()
            .collect()
        } else {
            self.pending
                .extract_if(|node| {
                    // Get all executable subjects, and remove them from pending
                    self.dag
                        .children(*node)
                        .iter(&self.dag)
                        .fold(true, |acc, (_e, ch)| self.done.is_visited(&ch)) // whether node is executable
                })
                .collect()
        };
        for n in traverse.iter() {
            for (e, p) in self.dag.parents(*n).iter(&self.dag) {
                self.pending.insert(p);
            }
        }
        self.ready = traverse;
    }
}

fn impl_at_most_one(pre: Lit, list: &[Lit], sat: &mut SatInstance) {
    let mut k = 0;
    while k < list.len() {
        let mut p = k + 1;
        while p < list.len() {
            let cl = clause!(-pre, -list[k], -list[p]);
            sat.add_clause(cl);
            p += 1;
        }
        k += 1;
    }
}

use thiserror::{self, Error};

#[derive(Error, Debug)]
#[error("Maybe a programming error. SAT solver can not find a solution")]
pub struct AllocationError;

pub macro Demand {
    ( $($typ:ident/$k:expr => $access:ident),+ ) => (
        HashMap::from_iter([$(( RsrcKey(std::any::TypeId::of::<$typ>(),$k) , ReqType::$access)),+])
    )
}

#[cfg(test)]
mod test;
