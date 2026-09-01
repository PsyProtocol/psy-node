use std::{fmt, ops::Deref};

use anyhow::{anyhow, Result};

#[derive(Clone, Debug, Eq, Hash, PartialEq, serde::Serialize)]
pub struct NetworkId(String);

impl NetworkId {
    pub fn new(value: &str) -> Result<Self> {
        let value = value.trim();
        if value.is_empty() {
            return Err(anyhow!("network must not be empty"));
        }
        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for NetworkId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
