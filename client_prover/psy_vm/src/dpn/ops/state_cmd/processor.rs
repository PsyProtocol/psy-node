use super::data::DPNStateCmd;
pub trait QDPNTargetResolver<F, U, B> {
    fn resolve_target(&self, target: &DPNStateCmd<u64>) -> F;
    fn resolve_target_array(&self, target: &DPNStateCmd<u64>) -> Vec<F>;
    fn resolve_hash(&self, target: &DPNStateCmd<u64>) -> [F; 4];
    fn resolve_hash160(&self, target: &DPNStateCmd<u64>) -> [U; 5];
    fn resolve_bool(&self, target: &DPNStateCmd<u64>) -> B;
    fn resolve_bool_array(&self, target: &DPNStateCmd<u64>) -> Vec<B>;
    fn resolve_u32(&self, target: &DPNStateCmd<u64>) -> U;
    fn resolve_u32_array(&self, target: &DPNStateCmd<u64>) -> Vec<U>;
}

pub trait QDPNStateCommandProcessor<F, U, B> {
    //fn process_command_vec<R: QDPNTargetResolver<F,U,B>>(&mut self, cmd:
    // &DPNStateCmd<u64>, resolver: &R) -> anyhow::Result<Vec<F>>;
    fn process_command_vec<R: QDPNTargetResolver<F, U, B>>(&mut self, cmd: &DPNStateCmd<u64>, resolver: &R) -> anyhow::Result<Vec<F>>;
}
