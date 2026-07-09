//! Exact-byte npm and PyPI artifact identity and safe, non-executing normalization.
//!
//! This crate treats every archive and every member as attacker-controlled data.
//! It does not extract members, invoke package tooling, resolve dependencies, or
//! execute lifecycle/build/import hooks.

mod archive;
mod error;
mod model;
mod normalize;

pub use error::{ArtifactModelError, NormalizationError};
pub use model::*;
pub use normalize::{detect_artifact_format, normalize_artifact, NormalizationLimits};
