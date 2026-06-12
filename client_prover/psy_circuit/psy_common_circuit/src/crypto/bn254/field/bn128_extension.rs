use plonky2::field::{extension::Extendable, types::Field};

use crate::crypto::bn254::field::{
    bn128_base::Bn128Base,
    extension::{dodecic::DodecicExtension, quadratic::QuadraticExtension, sextic::SexticExtension},
};

impl Extendable<2> for Bn128Base {
    type Extension = QuadraticExtension<Self>;

    const W: Self = Bn128Base::NEG_ONE;

    const DTH_ROOT: Self = Self(Bn128Base::NEG_ONE.0);

    const EXT_MULTIPLICATIVE_GROUP_GENERATOR: [Self; 2] = [
        Self([3, 0, 0, 0]), // 3 as base field element
        Self([0, 0, 0, 0]), // 0 as base field element
    ];
    const EXT_POWER_OF_TWO_GENERATOR: [Self; 2] = [
        Self([0x68c3488912edefaa, 0x8d087f6872aabf4f, 0x51e1a24709081231, 0x2259d6b14729c0fa]), // -1 as base field element
        Self([0, 0, 0, 0]),                                                                     // 0 as base field element
    ];
}

pub trait Bn128ExtConstants {
    const EXT_NONRESIDUE: [Bn128Base; 2];
    const FROBENIUS_COEFFS_EXT6_C1: [Bn128Base; 6];
    const FROBENIUS_COEFFS_EXT6_C2: [Bn128Base; 6];
    const FROBENIUS_COEFFS_EXT12_C1: [Bn128Base; 6];
}

impl Bn128ExtConstants for Bn128Base {
    const EXT_NONRESIDUE: [Bn128Base; 2] = [
        Bn128Base([0xf60647ce410d7ff7, 0x2f3d6f4dd31bd011, 0x2943337e3940c6d1, 0x1d9598e8a7e39857]),
        Bn128Base([0xd35d438dc58f0d9d, 0x0a78eb28f5c70b3d, 0x666ea36f7879462c, 0x0e0a77c19a07df2f]),
    ];
    const FROBENIUS_COEFFS_EXT6_C1: [Bn128Base; 6] = [
        Bn128Base([13075984984163199792, 3782902503040509012, 8791150885551868305, 1825854335138010348]),
        Bn128Base([7963664994991228759, 12257807996192067905, 13179524609921305146, 2767831111890561987]),
        Bn128Base([3697675806616062876, 9065277094688085689, 6918009208039626314, 2775033306905974752]),
        Bn128Base([0, 0, 0, 0]),
        Bn128Base([14532872967180610477, 12903226530429559474, 1868623743233345524, 2316889217940299650]),
        Bn128Base([12447993766991532972, 4121872836076202828, 7630813605053367399, 740282956577754197]),
    ];
    const FROBENIUS_COEFFS_EXT6_C2: [Bn128Base; 6] = [
        Bn128Base([8314163329781907090, 11942187022798819835, 11282677263046157209, 1576150870752482284]),
        Bn128Base([6763840483288992073, 7118829427391486816, 4016233444936635065, 2630958277570195709]),
        Bn128Base([8183898218631979349, 12014359695528440611, 12263358156045030468, 3187210487005268291]),
        Bn128Base([0, 0, 0, 0]),
        Bn128Base([4938922280314430175, 13823286637238282975, 15589480384090068090, 481952561930628184]),
        Bn128Base([3105754162722846417, 11647802298615474591, 13057042392041828081, 1660844386505564338]),
    ];
    const FROBENIUS_COEFFS_EXT12_C1: [Bn128Base; 6] = [
        Bn128Base([12653890742059813127, 14585784200204367754, 1278438861261381767, 212598772761311868]),
        Bn128Base([11683091849979440498, 14992204589386555739, 15866167890766973222, 1200023580730561873]),
        Bn128Base([14595462726357228530, 17349508522658994025, 1017833795229664280, 299787779797702374]),
        Bn128Base([0, 0, 0, 0]),
        Bn128Base([3914496794763385213, 790120733010914719, 7322192392869644725, 581366264293887267]),
        Bn128Base([12817045492518885689, 4440270538777280383, 11178533038884588256, 2767537931541304486]),
    ];
}

impl Extendable<6> for Bn128Base {
    type Extension = SexticExtension<Self>;

    const W: Self = Self([3, 0, 0, 0]); // 3 is a 6th root primitive element
    const DTH_ROOT: Self = Self([0x68c3488912edefaa, 0x8d087f6872aabf4f, 0x51e1a24709081231, 0x2259d6b14729c0fa]); // -1
    const EXT_MULTIPLICATIVE_GROUP_GENERATOR: [Self; 6] = [
        Self([3, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
    ];
    const EXT_POWER_OF_TWO_GENERATOR: [Self; 6] = [
        Self([0x68c3488912edefaa, 0x8d087f6872aabf4f, 0x51e1a24709081231, 0x2259d6b14729c0fa]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
    ];
}

impl Extendable<12> for Bn128Base {
    type Extension = DodecicExtension<Self>;

    const W: Self = Self([3, 0, 0, 0]);
    const DTH_ROOT: Self = Self([0x68c3488912edefaa, 0x8d087f6872aabf4f, 0x51e1a24709081231, 0x2259d6b14729c0fa]);
    const EXT_MULTIPLICATIVE_GROUP_GENERATOR: [Self; 12] = [
        Self([3, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
    ];
    const EXT_POWER_OF_TWO_GENERATOR: [Self; 12] = [
        Self([0x68c3488912edefaa, 0x8d087f6872aabf4f, 0x51e1a24709081231, 0x2259d6b14729c0fa]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
        Self([0, 0, 0, 0]),
    ];
}
