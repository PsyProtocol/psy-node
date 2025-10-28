use parth_core::pgoldilocks::QHashOut;
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOut, RichField}, plonk::config::AlgebraicHasher};
use psy_data::v1::qdata::user::PQEDUserLeaf;

pub trait AlgHashable<F: RichField + Extendable<D>, const D: usize> {
    fn p2_alghash<H: AlgebraicHasher<F>>(&self) -> HashOut<F>;
    fn p2_q_alghash<H: AlgebraicHasher<F>>(&self) -> QHashOut<F> {
        QHashOut(self.p2_alghash::<H>())
    }
}

impl<F: RichField + Extendable<D>, const D: usize> AlgHashable<F, D> for PQEDUserLeaf<F, QHashOut<F>> {
    fn p2_alghash<H: AlgebraicHasher<F>>(&self) -> HashOut<F> {

        let public_key_felts = self.public_key.0.elements;
        let user_state_tree_root_felts = self.user_state_tree_root.0.elements;

        H::hash_no_pad(&[
            public_key_felts[0],
            public_key_felts[1],
            public_key_felts[2],
            public_key_felts[3],
            user_state_tree_root_felts[0],
            user_state_tree_root_felts[1],
            user_state_tree_root_felts[2],
            user_state_tree_root_felts[3],
            self.balance,
            self.nonce,
            self.last_checkpoint_id,
            self.event_index,
            self.user_id,
        ])
    }
}