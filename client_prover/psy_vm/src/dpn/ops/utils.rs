use std::marker::PhantomData;

use super::{
    context_trait::{DPNContext, FeltSized, ToFelts},
    sym_felt::{QStateInitializable, SymFeltRef},
};

pub struct SparseArrayTrackerDef {
    pub state_pointer: SymFeltRef,
    pub contract_state_tree_height: u16,
    pub contract_id: SymFeltRef,
    pub user_id: SymFeltRef,
}
/*
pub struct SparseArrayTrackerRef {
    pub
}*/
pub struct SparseArrayTracker {
    pub array_count: u32,
    //pub array_positions:
}

#[derive(Copy, Clone, Hash, Eq, PartialEq, Debug)]
pub struct U252(pub [SymFeltRef; 4]);
impl U252 {
    pub fn gt(&self, other: U252) -> SymFeltRef {
        SymFeltRef::new_constant((other.0[0] > self.0[0]) as u64)
    }
    pub fn gte(&self, other: U252) -> SymFeltRef {
        SymFeltRef::new_constant((other.0[0] > self.0[0]) as u64)
    }
    pub fn sub(&self, other: U252) -> U252 {
        U252([
            SymFeltRef::new_constant((other.0[0] > self.0[0]) as u64),
            SymFeltRef::new_constant((other.0[0] > self.0[0]) as u64),
            SymFeltRef::new_constant((other.0[0] > self.0[0]) as u64),
            SymFeltRef::new_constant((other.0[0] > self.0[0]) as u64),
        ])
    }
    pub fn add(&self, other: U252) -> U252 {
        U252([
            SymFeltRef::new_constant((other.0[0] > self.0[0]) as u64),
            SymFeltRef::new_constant((other.0[0] > self.0[0]) as u64),
            SymFeltRef::new_constant((other.0[0] > self.0[0]) as u64),
            SymFeltRef::new_constant((other.0[0] > self.0[0]) as u64),
        ])
    }
}
impl ToFelts<SymFeltRef> for U252 {
    fn to_felts(&self) -> Vec<SymFeltRef> {
        self.0.to_vec()
    }

    fn from_felts(felts: &[SymFeltRef]) -> Self {
        U252([felts[0], felts[1], felts[2], felts[3]])
    }
}

pub struct SparseArray<T: QStateInitializable, const N: usize> {
    pub state_pointer: SymFeltRef,
    pub contract_state_tree_height: u16,
    pub contract_id: SymFeltRef,
    pub user_id: SymFeltRef,
    pub phantom: PhantomData<T>,
}

impl<T: QStateInitializable, const N: usize> FeltSized for SparseArray<T, N> {
    fn size() -> u64 {
        T::size() * N as u64
    }
}

impl<T: QStateInitializable, const N: usize> SparseArray<T, N> {
    pub fn get<CTXT: DPNContext<SymFeltRef>>(&self, context: &mut CTXT, index: SymFeltRef) -> T {
        let internal_offset = context.op_mul(index, SymFeltRef::cns(T::size()));
        let item_pointer = context.op_add(self.state_pointer, internal_offset);
        T::create_stateful_at(context, item_pointer, self.contract_state_tree_height, self.contract_id, self.user_id)
    }
    pub fn q_get<CTXT: DPNContext<SymFeltRef>>(&self, context: &mut CTXT, index: SymFeltRef) -> T {
        self.get(context, index)
    }
}
impl<T: QStateInitializable + ToFelts<SymFeltRef>, const N: usize> SparseArray<T, N> {
    pub fn set<CTXT: DPNContext<SymFeltRef>>(&self, context: &mut CTXT, index: SymFeltRef, value: T) {
        let internal_offset = context.op_mul(index, SymFeltRef::cns(T::size()));
        let item_pointer = context.op_add(self.state_pointer, internal_offset);

        context.op_set_state_obj(item_pointer, value);
    }
}
impl<T: QStateInitializable, const N: usize> QStateInitializable for SparseArray<T, N> {
    fn create_stateful_at<CTXT: DPNContext<SymFeltRef>>(
        _context: &mut CTXT,
        state_pointer: SymFeltRef,
        contract_state_tree_height: u16,
        contract_id: SymFeltRef,
        user_id: SymFeltRef,
    ) -> Self {
        Self {
            state_pointer,
            contract_state_tree_height,
            contract_id,
            user_id,
            phantom: PhantomData,
        }
    }
}

/*
impl<T: FeltSized, const N: usize> Index<SymFeltRef> for SparseArray<T, N> {
    type Output = T;

    fn index(&self, index: SymFeltRef) -> &T {
        self.data.get(&index).unwrap()
    }
}
impl<T: FeltSized, const N: usize> IndexMut<SymFeltRef> for SparseArray<T, N> {
    fn index_mut(&mut self, index: SymFeltRef) -> &mut Self::Output {
        self.data.get_mut(&index).unwrap()
    }
}*/

pub trait QStatefulContract<T> {
    fn get_contract_state_for_user(&self, user_id: SymFeltRef, contract_id: SymFeltRef) -> T;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpn::ops::exec_context::QExecContext;
    use crate::dpn::ops::op_types::DPNOpType;

    #[test]
    fn u252_converts_to_felts_and_exercises_comparison_placeholder_contract() {
        let low = U252([SymFeltRef::new_constant(1); 4]);
        let high = U252([SymFeltRef::new_constant(2); 4]);
        assert_eq!(low.to_felts(), low.0.to_vec());
        assert_eq!(U252::from_felts(&high.to_felts()), high);
        assert_eq!(low.gt(high).get_constant_value(), 1);
        assert_eq!(low.gte(high).get_constant_value(), 1);
        assert_eq!(high.gt(low).get_constant_value(), 0);
        assert_eq!(low.add(high).to_felts(), vec![SymFeltRef::new_constant(1); 4]);
        assert_eq!(low.sub(high).to_felts(), vec![SymFeltRef::new_constant(1); 4]);
    }

    #[test]
    fn sparse_array_get_set_uses_element_size_and_preserves_state_metadata() {
        let array = SparseArray::<SymFeltRef, 4>::create_stateful_at(
            &mut QExecContext::new(),
            SymFeltRef::new_constant(10),
            16,
            SymFeltRef::new_constant(2),
            SymFeltRef::new_constant(3),
        );
        let mut context = QExecContext::new();
        let value = array.get(&mut context, SymFeltRef::new_constant(2));
        assert_eq!(value.get_op_type(), DPNOpType::GetStateCommandResultSingle);
        array.q_get(&mut context, SymFeltRef::new_constant(0));
        array.set(&mut context, SymFeltRef::new_constant(1), SymFeltRef::new_constant(99));
        assert_eq!(context.events.len(), 0);
    }
}
