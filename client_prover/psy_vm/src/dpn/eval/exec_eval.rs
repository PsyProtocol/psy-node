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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpn::ops::context_trait::DPNContext;

    #[test]
    fn evaluates_requested_outputs_and_empty_output_selection() {
        let mut context = QExecContext::new();
        let input = context.add_input();
        let two = context.op_const(2);
        let output = context.op_add(input, two);

        assert_eq!(exec_eval_simple(vec![5], &context, Some(vec![output])), vec![7]);
        assert!(exec_eval_simple(vec![5], &context, None).is_empty());
    }

    #[test]
    #[should_panic(expected = "Assertion failed: values must match")]
    fn surfaces_failed_symbolic_assertions() {
        let mut context = QExecContext::new();
        let one = context.op_const(1);
        let two = context.op_const(2);
        context.assert_eq(one, two, "values must match");
        let _ = exec_eval_simple(vec![], &context, None);
    }
}
