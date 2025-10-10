use parth_core::{data::serializable::QPDSerializable, felt::QFelt64, protocol::core_types::{QFHashBase, QHashBase}};
use pser::{QBytesDeserialize, QBytesSerialize};

pub trait PsyDatatypes {
    type UserLeaf: QPDSerializable + QBytesSerialize + QBytesDeserialize;
    type PF: QFelt64;
    type PsyHash: QPDSerializable + QBytesSerialize + QBytesDeserialize + QHashBase + QFHashBase<Self::PF>;
}