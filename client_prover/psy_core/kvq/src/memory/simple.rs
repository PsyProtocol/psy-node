use std::{collections::BTreeMap, ops::Bound::Included, sync::Arc};

use parking_lot::RwLock;

use crate::traits::{KVQBinaryStore, KVQBinaryStoreAsync, KVQPair};

#[derive(Debug, Clone)]
pub struct KVQSimpleMemoryBackingStore {
    map: Arc<RwLock<BTreeMap<Vec<u8>, Vec<u8>>>>,
}
impl KVQSimpleMemoryBackingStore {
    pub fn new() -> Self {
        Self {
            map: Arc::new(RwLock::new(BTreeMap::new())),
        }
    }
    pub fn clear(&self) {
        self.map.write().clear();
    }
}

impl KVQBinaryStore for KVQSimpleMemoryBackingStore {
    fn get_exact(&self, key: &Vec<u8>) -> anyhow::Result<Vec<u8>> {
        match self.map.read().get(key) {
            Some(v) => Ok(v.to_owned()),
            None => anyhow::bail!("Key {} not found", hex::encode(&key)),
        }
    }

    fn get_many_exact(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut result = Vec::new();
        for key in keys {
            let r = <Self as KVQBinaryStore>::get_exact(self, key)?;
            result.push(r);
        }
        Ok(result)
    }

    fn get_leq(&self, key: &Vec<u8>, fuzzy_bytes: usize) -> anyhow::Result<Option<Vec<u8>>> {
        if fuzzy_bytes > key.len() {
            return Err(anyhow::anyhow!("Fuzzy bytes must be less than or equal to key length"));
        }

        let map = self.map.read();

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

            let rq = map.range((Included(base_key), Included(key.clone()))).next_back();

            if let Some((_, p)) = rq {
                Ok(Some(p.to_owned()))
            } else {
                Ok(None)
            }
        }
    }

    fn get_leq_kv(&self, key: &Vec<u8>, fuzzy_bytes: usize) -> anyhow::Result<Option<KVQPair<Vec<u8>, Vec<u8>>>> {
        if fuzzy_bytes > key.len() {
            return Err(anyhow::anyhow!("Fuzzy bytes must be less than or equal to key length"));
        }

        let map = self.map.read();

        if fuzzy_bytes == 0 {
            let result = map.range(..=key.clone()).next_back();
            match result {
                Some((k, v)) => Ok(Some(KVQPair {
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

            let rq = map.range((Included(base_key), Included(key.clone()))).next_back();

            if let Some((k, v)) = rq {
                Ok(Some(KVQPair {
                    key: k.to_owned(),
                    value: v.to_owned(),
                }))
            } else {
                Ok(None)
            }
        }
    }

    fn get_many_leq(&self, keys: &[Vec<u8>], fuzzy_bytes: usize) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        let mut results: Vec<Option<Vec<u8>>> = Vec::with_capacity(keys.len());
        for k in keys {
            let r = <Self as KVQBinaryStore>::get_leq(self, k, fuzzy_bytes)?;
            results.push(r.to_owned());
        }
        Ok(results)
    }

    fn get_many_leq_kv(&self, keys: &[Vec<u8>], fuzzy_bytes: usize) -> anyhow::Result<Vec<Option<KVQPair<Vec<u8>, Vec<u8>>>>> {
        let mut results: Vec<Option<KVQPair<Vec<u8>, Vec<u8>>>> = Vec::with_capacity(keys.len());
        for k in keys {
            let r = <Self as KVQBinaryStore>::get_leq_kv(self, k, fuzzy_bytes)?;
            results.push(r);
        }
        Ok(results)
    }

    fn get_exact_if_exists(&self, key: &Vec<u8>) -> anyhow::Result<Option<Vec<u8>>> {
        let result = self.map.read().get(key).cloned();
        if result.is_some() {
            Ok(Some(result.unwrap()))
        } else {
            Ok(None)
        }
    }
    /*

    fn get_range_kv(
        &self,
        min_included: &Vec<u8>,
        max_included: &Vec<u8>,
    ) -> anyhow::Result<Vec<KVQPair<Vec<u8>, Vec<u8>>>> {
        let rq = self
            .map
            .range((
                Included(min_included.to_vec()),
                Included(max_included.to_vec()),
            ))
            .map(|(k, v)| KVQPair {
                key: k.to_owned(),
                value: v.to_owned(),
            })
            .collect::<Vec<_>>();
        Ok(rq)
    }

    fn get_prefix_range_kv(
        &self,
        prefix: &Vec<u8>,
        fuzzy_bytes: usize,
    ) -> anyhow::Result<Vec<KVQPair<Vec<u8>, Vec<u8>>>> {
        let mut base_key = vec![0u8; prefix.len() + fuzzy_bytes];
        base_key[0..prefix.len()].copy_from_slice(prefix);

        let mut key_end = base_key.to_vec();
        for i in ((prefix.len() - fuzzy_bytes)..prefix.len()) {
            key_end[i] = 0xff;
        }
        Ok(self
            .map
            .range((Included(base_key), Included(key_end)))
            .map(|(k, v)| KVQPair {
                key: k.to_owned(),
                value: v.to_owned(),
            })
            .collect::<Vec<_>>())
    }*/

    fn get_fuzzy_range_leq_kv(&self, key: &Vec<u8>, fuzzy_bytes: usize) -> anyhow::Result<Vec<KVQPair<Vec<u8>, Vec<u8>>>> {
        let key_end = key.to_vec();
        let mut base_key = key.to_vec();
        let key_len = base_key.len();
        if fuzzy_bytes > key_len {
            return Err(anyhow::anyhow!("Fuzzy bytes must be less than or equal to key length"));
        }

        for i in 0..fuzzy_bytes {
            base_key[key_len - i - 1] = 0;
        }

        let map = self.map.read();
        Ok(map
            .range((Included(base_key), Included(key_end)))
            .map(|(k, v)| KVQPair {
                key: k.to_owned(),
                value: v.to_owned(),
            })
            .collect::<Vec<_>>())
    }

    // Write operations
    fn set(&self, key: Vec<u8>, value: Vec<u8>) -> anyhow::Result<()> {
        self.map.write().insert(key, value);
        Ok(())
    }

    fn set_ref(&self, key: &Vec<u8>, value: &Vec<u8>) -> anyhow::Result<()> {
        self.map.write().insert(key.clone(), value.clone());
        Ok(())
    }

    fn set_many_ref<'a>(&self, items: &[KVQPair<&'a Vec<u8>, &'a Vec<u8>>]) -> anyhow::Result<()> {
        let mut map = self.map.write();
        for item in items {
            map.insert(item.key.clone(), item.value.clone());
        }
        Ok(())
    }

    fn set_many_vec(&self, items: Vec<KVQPair<Vec<u8>, Vec<u8>>>) -> anyhow::Result<()> {
        let mut map = self.map.write();
        for item in items {
            map.insert(item.key, item.value);
        }
        Ok(())
    }

    fn delete(&self, key: &Vec<u8>) -> anyhow::Result<bool> {
        match self.map.write().remove(key) {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }

    fn delete_many(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<bool>> {
        let mut result = Vec::with_capacity(keys.len());
        let mut map = self.map.write();
        for key in keys {
            let r = match map.remove(key) {
                Some(_) => true,
                None => false,
            };
            result.push(r);
        }
        Ok(result)
    }

    fn set_many_split_ref(&self, keys: &[Vec<u8>], values: &[Vec<u8>]) -> anyhow::Result<()> {
        if keys.len() != values.len() {
            anyhow::bail!("Keys and values must have the same length");
        } else {
            let mut map = self.map.write();
            for i in 0..keys.len() {
                map.insert(keys[i].clone(), values[i].clone());
            }
            Ok(())
        }
    }
}

#[async_trait::async_trait]
impl KVQBinaryStoreAsync for KVQSimpleMemoryBackingStore {
    async fn get_exact(&self, key: &Vec<u8>) -> anyhow::Result<Vec<u8>> {
        <Self as KVQBinaryStore>::get_exact(self, key)
    }

    async fn get_exact_if_exists(&self, key: &Vec<u8>) -> anyhow::Result<Option<Vec<u8>>> {
        <Self as KVQBinaryStore>::get_exact_if_exists(self, key)
    }

    async fn get_many_exact(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<Vec<u8>>> {
        <Self as KVQBinaryStore>::get_many_exact(self, keys)
    }

    async fn get_leq(&self, key: &Vec<u8>, fuzzy_bytes: usize) -> anyhow::Result<Option<Vec<u8>>> {
        <Self as KVQBinaryStore>::get_leq(self, key, fuzzy_bytes)
    }

    async fn get_leq_kv(&self, key: &Vec<u8>, fuzzy_bytes: usize) -> anyhow::Result<Option<KVQPair<Vec<u8>, Vec<u8>>>> {
        <Self as KVQBinaryStore>::get_leq_kv(self, key, fuzzy_bytes)
    }

    async fn get_many_leq(&self, keys: &[Vec<u8>], fuzzy_bytes: usize) -> anyhow::Result<Vec<Option<Vec<u8>>>> {
        <Self as KVQBinaryStore>::get_many_leq(self, keys, fuzzy_bytes)
    }

    async fn get_many_leq_kv(&self, keys: &[Vec<u8>], fuzzy_bytes: usize) -> anyhow::Result<Vec<Option<KVQPair<Vec<u8>, Vec<u8>>>>> {
        <Self as KVQBinaryStore>::get_many_leq_kv(self, keys, fuzzy_bytes)
    }

    async fn get_fuzzy_range_leq_kv(&self, key: &Vec<u8>, fuzzy_bytes: usize) -> anyhow::Result<Vec<KVQPair<Vec<u8>, Vec<u8>>>> {
        <Self as KVQBinaryStore>::get_fuzzy_range_leq_kv(self, key, fuzzy_bytes)
    }

    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> anyhow::Result<()> {
        <Self as KVQBinaryStore>::set(self, key, value)
    }

    async fn set_ref(&self, key: &Vec<u8>, value: &Vec<u8>) -> anyhow::Result<()> {
        <Self as KVQBinaryStore>::set_ref(self, key, value)
    }

    async fn set_many_ref<'a>(&self, items: &[KVQPair<&'a Vec<u8>, &'a Vec<u8>>]) -> anyhow::Result<()> {
        <Self as KVQBinaryStore>::set_many_ref(self, items)
    }

    async fn set_many_vec(&self, items: Vec<KVQPair<Vec<u8>, Vec<u8>>>) -> anyhow::Result<()> {
        <Self as KVQBinaryStore>::set_many_vec(self, items)
    }

    async fn set_many_split_ref(&self, keys: &[Vec<u8>], values: &[Vec<u8>]) -> anyhow::Result<()> {
        <Self as KVQBinaryStore>::set_many_split_ref(self, keys, values)
    }

    async fn delete(&self, key: &Vec<u8>) -> anyhow::Result<bool> {
        <Self as KVQBinaryStore>::delete(self, key)
    }

    async fn delete_many(&self, keys: &[Vec<u8>]) -> anyhow::Result<Vec<bool>> {
        <Self as KVQBinaryStore>::delete_many(self, keys)
    }

    async fn set_and_delete_many(&self, sets: &[KVQPair<&Vec<u8>, &Vec<u8>>], deletes: &[Vec<u8>]) -> anyhow::Result<()> {
        <Self as KVQBinaryStore>::set_and_delete_many(self, sets, deletes)?;
        Ok(())
    }
}
