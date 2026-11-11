//! What the encoded form of the domain's records shares: the error of a value made of several
//! parts, and the form of a number that is not finite.
//!
//! Behind the `serde` feature, the records of a catalog (`Sources`, `Authority`), the events
//! behind a state, and how a change loosens (`Loosening`) are encoded so that decoding a value
//! with a checking constructor goes only through that constructor (FR68). A type with a private
//! field is encoded as the input of its constructor (a `Raw` kept private in the module of the
//! type), a type of plain data as it is. This module is the lowest layer of the domain, as
//! `authority` is: it uses no other module, and `arch-lint.toml` keeps it so, so each module of
//! the domain can use what is here.
//!
//! ```text
//! JSON ── Deserialize ──▶ Raw (private, in the module of the type) ── TryFrom ──▶ constructor ──▶ T
//! T    ── From<T> ──────▶ Raw ── Serialize ──▶ JSON
//! ```
//!
//! This encoding is a tool for mapping the core's values, not the form a store keeps them in: the
//! core keeps no version of it and no pinned sample of what it writes. A store has its own DTOs,
//! its own version and its own pinned samples, and maps between them and the core's values.

use std::fmt;

/// Every error a constructor found, as the error of decoding a value that has several: the
/// constructors of [`Sources`](super::set::Sources) and of
/// [`PolicyGraph`](super::policy::PolicyGraph) return all they find, and decoding reports them as
/// one text, since serde carries an error as text.
#[derive(Debug)]
pub(crate) struct Errors<E>(pub(crate) Vec<E>);

impl<E: fmt::Display> fmt::Display for Errors<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (at, error) in self.0.iter().enumerate() {
            if at > 0 {
                f.write_str("; ")?;
            }
            error.fmt(f)?;
        }
        Ok(())
    }
}

/// The encoded form of an `f64` that may not be finite, for `serde(with)`.
///
/// The domain takes NaN for a score (`Body::Measured`) and for an answer (`Body::Classified`),
/// and `serde_json` writes a number that is not finite as `null`, which it cannot read back as an
/// `f64`: a record that can be written and not read. A finite number is encoded as a JSON number,
/// and any other as the text `"NaN"`, `"inf"` or `"-inf"`. A NaN keeps no payload.
pub(crate) mod float {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// A number as it is encoded.
    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    enum Float {
        Finite(f64),
        Special(NonFinite),
    }

    /// A number that is not finite, as the text it is encoded as.
    #[derive(Serialize, Deserialize)]
    enum NonFinite {
        #[serde(rename = "NaN")]
        NaN,
        #[serde(rename = "inf")]
        Inf,
        #[serde(rename = "-inf")]
        NegInf,
    }

    impl From<f64> for Float {
        fn from(value: f64) -> Self {
            if value.is_finite() {
                Self::Finite(value)
            } else if value.is_nan() {
                Self::Special(NonFinite::NaN)
            } else if value > 0.0 {
                Self::Special(NonFinite::Inf)
            } else {
                Self::Special(NonFinite::NegInf)
            }
        }
    }

    impl From<Float> for f64 {
        fn from(float: Float) -> Self {
            match float {
                Float::Finite(value) => value,
                Float::Special(NonFinite::NaN) => f64::NAN,
                Float::Special(NonFinite::Inf) => f64::INFINITY,
                Float::Special(NonFinite::NegInf) => f64::NEG_INFINITY,
            }
        }
    }

    /// Writes `value`: a number when it is finite, else its text.
    pub(crate) fn serialize<S: Serializer>(value: &f64, serializer: S) -> Result<S::Ok, S::Error> {
        Float::from(*value).serialize(serializer)
    }

    /// Reads a number, or the text of one that is not finite.
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<f64, D::Error> {
        Float::deserialize(deserializer).map(f64::from)
    }
}
