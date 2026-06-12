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
