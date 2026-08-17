//! Validated CQL keyspace identifiers.
//!
//! Every rollback adapter interpolates a keyspace into its CQL, so the name has
//! to be a checked unquoted identifier rather than a caller-supplied string.
//! Table names are never supplied by callers at all; they are resolved from the
//! typed physical registry.

use std::{error::Error, fmt};

/// Longest identifier ScyllaDB accepts for a keyspace.
const MAX_KEYSPACE_NAME_LEN: usize = 48;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidCqlKeyspaceName(pub String);

impl fmt::Display for InvalidCqlKeyspaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid unquoted CQL keyspace identifier {:?}", self.0)
    }
}

impl Error for InvalidCqlKeyspaceName {}

/// A validated unquoted CQL identifier.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct CqlKeyspaceName(String);

impl CqlKeyspaceName {
    pub fn try_new(name: impl Into<String>) -> Result<Self, InvalidCqlKeyspaceName> {
        let name = name.into();
        let mut chars = name.chars();
        let valid_first = chars
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic());
        let valid_rest = chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric());
        if !name.is_empty() && name.len() <= MAX_KEYSPACE_NAME_LEN && valid_first && valid_rest {
            Ok(Self(name))
        } else {
            Err(InvalidCqlKeyspaceName(name))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_identifiers_production_setup_actually_uses() {
        for name in ["psy", "psy_node_1", "_leading_underscore", "a"] {
            assert_eq!(
                CqlKeyspaceName::try_new(name).map(|ks| ks.as_str().to_owned()),
                Ok(name.to_owned()),
            );
        }
    }

    #[test]
    fn rejects_everything_that_would_need_quoting_or_escape_cql() {
        for name in [
            "",
            "1leading_digit",
            "has-hyphen",
            "has space",
            "has\"quote",
            "drop;table",
            "unicodé",
            "a.b",
        ] {
            assert_eq!(
                CqlKeyspaceName::try_new(name),
                Err(InvalidCqlKeyspaceName(name.to_owned())),
                "{name:?} must not be accepted",
            );
        }
    }

    #[test]
    fn rejects_names_longer_than_scylla_allows() {
        let longest = "k".repeat(MAX_KEYSPACE_NAME_LEN);
        assert!(CqlKeyspaceName::try_new(longest.clone()).is_ok());
        let too_long = "k".repeat(MAX_KEYSPACE_NAME_LEN + 1);
        assert_eq!(
            CqlKeyspaceName::try_new(too_long.clone()),
            Err(InvalidCqlKeyspaceName(too_long)),
        );
    }
}
