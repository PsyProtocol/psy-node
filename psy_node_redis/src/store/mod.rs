//mod core_bb8;
mod core_fred;
//mod core_rustis;
// mod ephemeral;
//pub use ephemeral::*;
//pub use core_bb8::*;

pub type StandardRedisStore = core_fred::StandardFredRedisStore;
pub use core_fred::*;