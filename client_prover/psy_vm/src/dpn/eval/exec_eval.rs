use super::{cache::SimpleEvalCache, simple::DummyContextEvalInput, traits::ContextEval};
use crate::dpn::ops::{exec_context::QExecContext, sym_felt::SymFeltRef};

pub fn exec_eval_simple(inputs: Vec<u64>, ctx: &QExecContext, output: Option<Vec<SymFeltRef>>) -> Vec<u64> {
    let mut cache = SimpleEvalCache::new();
    let input = DummyContextEvalInput::new(inputs);

    //for i in 0..ctx.state_cmd_store.any_order_cmd_map

    /*
    for i in 0..ctx.set_state_commands.len() {
        for k in 0..ctx.get_self_contract_state_commands[i].len() {
            let _ = ctx.store.resolve_felt_ref_cached(ctx.get_self_contract_state_commands[i][k], &input, &mut cache);
        }
    }*/
    for assertion in ctx.assertions.iter() {
        let left = ctx.store.resolve_felt_ref_cached(assertion.left, &input, &mut cache);
        let right = ctx.store.resolve_felt_ref_cached(assertion.right, &input, &mut cache);
        assert_eq!(left, right, "Assertion failed: {}", assertion.message);
    }
    if let Some(output) = output {
        output
            .iter()
            .map(|felt_ref| ctx.store.resolve_felt_ref_cached(*felt_ref, &input, &mut cache))
            .collect()
    } else {
        vec![]
    }
}
