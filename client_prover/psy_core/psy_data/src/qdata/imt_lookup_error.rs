use std::fmt;

/// Absence is different from a failed lookup. Providers translate their wire
/// errors into this type; callers decide whether absence is valid for the operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImtLookupNotFound {
    Key,
    LeafPreimage { leaf_index: u64 },
    Predecessor,
}

impl fmt::Display for ImtLookupNotFound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key => write!(f, "Key not found in IMT"),
            Self::LeafPreimage { leaf_index } => write!(f, "Leaf preimage not found at index {}", leaf_index),
            Self::Predecessor => write!(f, "No predecessor found for key"),
        }
    }
}

impl std::error::Error for ImtLookupNotFound {}

impl ImtLookupNotFound {
    pub fn matches(self, error: &anyhow::Error) -> bool {
        error.downcast_ref::<Self>() == Some(&self)
    }

    /// Only the expected kind of absence is optional; all other failures survive.
    pub fn optional<T>(self, result: anyhow::Result<T>) -> anyhow::Result<Option<T>> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(error) if self.matches(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn imt_absence_survives_context_but_does_not_match_other_failures() {
        let missing = ImtLookupNotFound::LeafPreimage { leaf_index: 18157 };
        let error = anyhow::Error::new(missing).context("loading insert slot");
        assert_eq!(missing.optional::<u64>(Err(error)).unwrap(), None);
        assert_eq!(missing.optional(Ok(7)).unwrap(), Some(7));
        for error in [
            anyhow::anyhow!("Leaf preimage not found at index 18157"),
            anyhow::anyhow!("database timeout"),
            anyhow::anyhow!("connection reset"),
            anyhow::Error::new(ImtLookupNotFound::Key),
            anyhow::Error::new(ImtLookupNotFound::LeafPreimage { leaf_index: 18158 }),
        ] {
            assert!(missing.optional::<u64>(Err(error)).is_err());
        }
    }

    #[test]
    fn imt_remote_predecessor_errors_are_not_absence() {
        assert!(ImtLookupNotFound::Predecessor.optional::<u64>(Err(anyhow::anyhow!("RPC timeout"))).is_err());
        assert_eq!(ImtLookupNotFound::Predecessor.optional::<u64>(Err(ImtLookupNotFound::Predecessor.into())).unwrap(), None);
    }
}
