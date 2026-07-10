//! Authentication primitives for Artifact Review v2 evidence.
//!
//! This crate is a trusted-control-plane boundary. It owns cryptographic key
//! resolution, canonical signed bytes, unpredictable single-use challenges,
//! replay/equivocation handling, and lineage compare-and-swap. It deliberately
//! does not execute a provider and never grants allow authority.

mod aggregate;
mod challenge;
mod error;
mod identity;
mod wire;

pub use aggregate::*;
pub use challenge::*;
pub use error::*;
pub use identity::*;
pub use wire::*;
