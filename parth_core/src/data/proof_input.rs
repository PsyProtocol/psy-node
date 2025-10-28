#[pderive::serialize_clone]
pub struct CircuitInputWithDependencies<InputWitness, JobId>
{
    pub input: InputWitness,
    pub dependencies: Vec<JobId>,
}
impl<InputWitness, JobId> CircuitInputWithDependencies<InputWitness, JobId> {
    pub fn new(input: InputWitness, job_id: JobId) -> Self {
        Self { input, dependencies: vec![job_id] }
    }
}