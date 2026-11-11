//! What the stored form of the domain's records shares: its version, the error of a value made
//! of several parts, and the form of a number that is not finite.
//!
//! Behind the `serde` feature, the records of a catalog (`Sources`, `Authority`) and the events
//! behind a state are encoded so that decoding a value with a checking constructor goes only
//! through that constructor (FR61). A type with a private field is stored as the input of its
//! constructor (a `Raw` kept private in the module of the type), a type of plain data as it is.
//! This module is the lowest layer of the domain, as `authority` is: it uses no other module, and
//! `arch-lint.toml` keeps it so, so each module of the domain can use what is here.
//!
//! ```text
//! JSON ── Deserialize ──▶ Raw (private, in the module of the type) ── TryFrom ──▶ constructor ──▶ T
//! T    ── From<T> ──────▶ Raw ── Serialize ──▶ JSON
//! ```
//!
//! The stored form is versioned by [`VERSION`]. A change of its shape changes the golden form that
//! `tests/stored.rs` compares it with, and that test fails until the version is raised.

use std::fmt;

/// The version of the stored form. Raise it when the golden form changes: a name of a field or of
/// a variant, or the shape of a value, that the stored form has. An older version stays readable
/// to whoever keeps the records and brings them up to this one.
pub const VERSION: u32 = 1;

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

/// The stored form of an `f64` that may not be finite, for `serde(with)`.
///
/// The domain takes NaN for a score (`Body::Measured`) and for an answer (`Body::Classified`),
/// and `serde_json` writes a number that is not finite as `null`, which it cannot read back as an
/// `f64`: a record that can be written and not read. A finite number is stored as a JSON number,
/// and any other as the text `"NaN"`, `"inf"` or `"-inf"`. A NaN keeps no payload.
pub(crate) mod float {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    /// A number as it is stored.
    #[derive(Serialize, Deserialize)]
    #[serde(untagged)]
    enum Float {
        Finite(f64),
        Special(NonFinite),
    }

    /// A number that is not finite, as the text it is stored as.
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
