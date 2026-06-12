use std::fmt::Debug;

use plonky2::hash::hash_types::RichField;
use psy_client_common::{data::qhashout::QHashOut, job::id::QProvingJobDataID};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::{AggStateTrackableInput, AggStateTrackableWithEventsInput, AggStateTransition, AggStateTransitionWithEvents};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(bound = "for<'de2> I: Deserialize<'de2>")]
pub struct CircuitInputWithJobId<I: Debug + Clone + Serialize + PartialEq> {
    pub input: I,
    pub job_id: QProvingJobDataID,
}
#[derive(Debug, Copy, Clone, Deserialize, Serialize, PartialEq)]
pub struct DummyCircuitInputWithJobId(pub QProvingJobDataID);

impl<F: RichField> AggStateTrackableInput<F> for DummyCircuitInputWithJobId {
    fn get_state_transition(&self) -> AggStateTransition<F> {
        AggStateTransition {
            state_transition_start: QHashOut::ZERO,
            state_transition_end: QHashOut::ZERO,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(bound = "for<'de2> I: Deserialize<'de2>")]
pub struct CircuitInputWithDependencies<I: Debug + Clone + Serialize + PartialEq> {
    pub input: I,
    pub dependencies: Vec<QProvingJobDataID>,
}
impl<I: Debug + Clone + Serialize + PartialEq> CircuitInputWithJobId<I> {
    pub fn new(input: I, job_id: QProvingJobDataID) -> Self {
        Self { input, job_id }
    }
}
impl<I: Debug + Clone + Serialize + DeserializeOwned + PartialEq + AggStateTrackableInput<F>, F: RichField> AggStateTrackableInput<F>
    for CircuitInputWithJobId<I>
{
    fn get_state_transition(&self) -> AggStateTransition<F> {
        self.input.get_state_transition()
    }
}

impl<I: Debug + Clone + Serialize + DeserializeOwned + PartialEq + AggStateTrackableWithEventsInput<F>, F: RichField>
    AggStateTrackableWithEventsInput<F> for CircuitInputWithJobId<I>
{
    fn get_state_transition_with_events(&self) -> AggStateTransitionWithEvents<F> {
        self.input.get_state_transition_with_events()
    }
}
