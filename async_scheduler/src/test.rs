use crate::*;
use dashmap::DashMap;

impl Key for u8 {}
impl SKey for u8 {}
impl TKey for u8 {}

struct ExampleSubject {
    /// Key should be something small, low-cost.
    subject_key: u8,
}

#[derive(Default)]
/// Will be passed to tasks as a &SharedState (shared reference)
struct SharedState {
    shared: String,
    ra: DashMap<u8, ResourceA>,
    rb: DashMap<u8, ResourceB>,
}

struct ResourceA(u8);
struct ResourceB(u8);

impl ScheSubject for ExampleSubject {
    type RKey = u8;
    type E = ();
    type GS = SharedState;
    type S = Stages;
    type SK = u8;
    type TK = u8;
    fn initial_status(&self) -> Self::S {
        Stages::Prepare
    }
    fn subject_key(&self) -> &Self::SK {
        &self.subject_key
    }
    fn next_task<'f>(
        &'f self,
        status: Self::S,
    ) -> Vec<FnPlan<'f, Self::SK, Self::TK, Self::RKey, Self::GS, Self::E, Self::S>> {
        match status {
            Stages::Prepare => [if self.subject_key == 0 {
                FnPlan {
                    tkey: 0,
                    subject: self.subject_key,
                    req: Demand!(ResourceA/1 => R, ResourceB/2 => R),
                    exec: Some(Box::new(move |shared: &Self::GS| {
                        Box::pin(async move {
                            let r1 = shared.ra.get(&1);
                            let r2 = shared.rb.get(&2);
                            println!("Subject {:?} from {:?}", self.subject_key, status);
                            Ok(())
                        })
                    })),
                    result: Stages::Alpha,
                }
            } else {
                FnPlan {
                    tkey: 0,
                    subject: self.subject_key,
                    req: Demand!(ResourceA/1 => W, ResourceB/2 => R),
                    exec: Some(Box::new(move |shared: &Self::GS| {
                        Box::pin(async move {
                            let r1 = shared.ra.get(&1);
                            let r2 = shared.rb.get(&2);
                            println!("Subject {:?} from {:?}", self.subject_key, status);
                            Ok(())
                        })
                    })),
                    result: Stages::Alpha,
                }
            }]
            .into(),
            Stages::Alpha => [FnPlan {
                tkey: 0,
                subject: self.subject_key,
                req: Demand!(ResourceA/1 => R, ResourceB/2 => R),
                exec: Some(Box::new(move |shared: &Self::GS| {
                    Box::pin(async move {
                        let r1 = shared.ra.get(&1);
                        let r2 = shared.rb.get(&2);
                        println!("Subject {:?} from {:?}", self.subject_key, status);
                        Ok(())
                    })
                })),
                result: Stages::Beta,
            }]
            .into(),
            Stages::Beta => [].into(),
        }
    }
}

#[derive(Clone, Debug)]
enum Stages {
    Prepare,
    Alpha,
    Beta,
}

impl NodeStatusT for Stages {
    fn node_status(&self) -> NodeStatus {
        match &self {
            Self::Prepare | Self::Alpha => NodeStatus::Undone,
            _ => NodeStatus::Done,
        }
    }
}

#[async_std::test]
async fn example() -> Result<()> {
    let mut sche = AsyncScheduler::default();
    let mut global = SharedState::default();
    sche.update(Box::new(ExampleSubject { subject_key: 0 }), &[])?;
    let k = sche.update(Box::new(ExampleSubject { subject_key: 1 }), &[1]);
    assert!(k.is_err());
    sche.update(Box::new(ExampleSubject { subject_key: 1 }), &[0]);
    sche.upkeep(&global).await?;
    sche.upkeep(&global).await?;
    sche.update(Box::new(ExampleSubject { subject_key: 2 }), &[])?;
    sche.upkeep(&global).await?;

    Ok(())
}
