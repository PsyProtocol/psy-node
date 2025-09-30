
use std::collections::BTreeMap;
use std::collections::Bound::Included;
use std::sync::{Arc, RwLock};

use crate::common::core::store::qpd_store::{QPDBinaryStoreReader, QPDBinaryStoreWriter};
use crate::common::core::serializable::QPDPair;

#[derive(Debug, Clone)]
pub struct QPDSimpleMemoryBackingStore {
    map: Arc<RwLock<BTreeMap<Vec<u8>, Vec<u8>>>>,
}

impl QPDSimpleMemoryBackingStore {
    pub fn new() -> Self {
        Self {
            map: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }

    pub fn clear(&self) {
        self.map.write().unwrap().clear();
    }
}

impl Default for QPDSimpleMemoryBackingStore {
    fn default() -> Self {
        Self::new()
    }
}

impl QPDBinaryStoreReader for QPDSimpleMemoryBackingStore {
    fn get_exact_if_exists(&self, key: &Vec<u8>) -> anyhow::Result<Option<Vec<u8>>> {
        let result = self.map.read().unwrap().get(key).cloned();
        Ok(result)
    }

    fn get_exact(&self, key: &Vec<u8>) -> anyhow::Result<Vec<u8>> {
        match self.map.read().unwrap().get(key) {
            Some(v) => Ok(v.to_owned()),
            None => anyhow::bail!("Key {} not found", hex::encode(key)),
        }
    }

    fn get_many_exact(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut result = Vec::new();
        for key in keys {
            let r = self.get_exact(key)?;
            result.push(r);
        }
        Ok(result)
    }

    fn get_leq(&self, key: &Vec<u8>, fuzzy_bytes: usize) -> anyhow::Result<Option<Vec<u8>>> {
        if fuzzy_bytes > key.len() {
            return Err(anyhow::anyhow!(
                "Fuzzy bytes must be less than or equal to key length"
            ));
        }

        let map = self.map.read().unwrap();

        if fuzzy_bytes == 0 {
            let result = map.range(..=key.clone()).next_back();
            match result {
                Some((_, v)) => Ok(Some(v.clone())),
                None => Ok(None),
            }
        } else {
            let mut base_key = key.clone();
            let key_len = base_key.len();
            for i in 0..fuzzy_bytes {
                base_key[key_len - i - 1] = 0;
            }

            let rq = map
                .range((Included(base_key), Included(key.clone())))
                .next_back();

            if let Some((_, p)) = rq {
                Ok(Some(p.to_owned()))
            } else {
                Ok(None)
            }
        }
    }

    fn get_fuzzy_range_leq_kv(
        &self,
        key: &Vec<u8>,
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Vec<QPDPair<Vec<u8>, Vec<u8>>>> {
        let key_end = key.to_vec();
        let mut base_key = key.to_vec();
        let key_len = base_key.len();
        if fuzzy_bytes > key_len {
            return Err(anyhow::anyhow!(
                "Fuzzy bytes must be less than or equal to key length"
            ));
        }

        for i in 0..fuzzy_bytes {
            base_key[key_len - i - 1] = 0;
        }

        let map = self.map.read().unwrap();
        Ok(map
            .range((Included(base_key), Included(key_end)))
            .map(|(k, v)| QPDPair {
                key: k.to_owned(),
                value: v.to_owned(),
            })
            .collect::<Vec<_>>())
    }

    fn get_leq_kv(
        &self,
        key: &Vec<u8>,
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Option<QPDPair<Vec<u8>, Vec<u8>>>> {
        if fuzzy_bytes > key.len() {
            return Err(anyhow::anyhow!(
                "Fuzzy bytes must be less than or equal to key length"
            ));
        }

        let map = self.map.read().unwrap();

        if fuzzy_bytes == 0 {
            let result = map.range(..=key.clone()).next_back();
            match result {
                Some((k, v)) => Ok(Some(QPDPair {
                    key: k.clone(),
                    value: v.clone(),
                })),
                None => Ok(None),
            }
        } else {
            let mut base_key = key.clone();
            let key_len = base_key.len();
            for i in 0..fuzzy_bytes {
                base_key[key_len - i - 1] = 0;
            }

            let rq = map
                .range((Included(base_key), Included(key.clone())))
                .next_back();

            if let Some((k, v)) = rq {
                Ok(Some(QPDPair {
                    key: k.to_owned(),
                    value: v.to_owned(),
                }))
            } else {
                Ok(None)
            }
        }
    }

    fn get_many_leq(
        &self,
        keys: &[Vec<u8>],
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        let mut results: Vec<Option<Vec<u8>>> = Vec::with_capacity(keys.len());
        for k in keys {
            let r = self.get_leq(k, fuzzy_bytes)?;
            results.push(r.to_owned());
        }
        Ok(results)
    }

    fn get_many_leq_kv(
        &self,
        keys: &[Vec<u8>],
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Vec<Option<QPDPair<Vec<u8>, Vec<u8>>>>> {
        let mut results: Vec<Option<QPDPair<Vec<u8>, Vec<u8>>>> = Vec::with_capacity(keys.len());
        for k in keys {
            let r = self.get_leq_kv(k, fuzzy_bytes)?;
            results.push(r);
        }
        Ok(results)
    }
}

impl QPDBinaryStoreWriter for QPDSimpleMemoryBackingStore {
    fn set(&self, key: Vec<u8>, value: Vec<u8>) -> anyhow::Result<()> {
        self.map.write().unwrap().insert(key, value);
        Ok(())
    }

    fn set_ref(&self, key: &Vec<u8>, value: &Vec<u8>) -> anyhow::Result<()> {
        self.map
            .write()
            .unwrap()
            .insert(key.clone(), value.clone());
        Ok(())
    }

    fn set_many_ref<'a>(
        &self,
        items: &[QPDPair<&'a Vec<u8>, &'a Vec<u8>>],
    ) -> anyhow::Result<()> {
        let mut map = self.map.write().unwrap();
        for item in items {
            map.insert(item.key.clone(), item.value.clone());
        }
        Ok(())
    }

    fn set_many_vec(&self, items: Vec<QPDPair<Vec<u8>, Vec<u8>>>) -> anyhow::Result<()> {
        let mut map = self.map.write().unwrap();
        for item in items {
            map.insert(item.key, item.value);
        }
        Ok(())
    }

    fn set_many_split_ref(&self, keys: &[Vec<u8>], values: &[Vec<u8>]) -> anyhow::Result<()> {
        if keys.len() != values.len() {
            anyhow::bail!("Keys and values must have the same length");
        } else {
            let mut map = self.map.write().unwrap();
            for i in 0..keys.len() {
                map.insert(keys[i].clone(), values[i].clone());
            }
            Ok(())
        }
    }

    fn delete(&self, key: &Vec<u8>) -> anyhow::Result<bool> {
        match self.map.write().unwrap().remove(key) {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }

    fn delete_many(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<bool>> {
        let mut result = Vec::with_capacity(keys.len());
        let mut map = self.map.write().unwrap();
        for key in keys {
            let r = match map.remove(key) {
                Some(_) => true,
                None => false,
            };
            result.push(r);
        }
        Ok(result)
    }
}