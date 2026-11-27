pub mod constants;
pub mod permutation;
pub mod state;
pub mod tag;
pub mod transform;

pub use tag::{IntegrityError, compute_tag, verify_tag};
