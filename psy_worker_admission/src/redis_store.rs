use async_trait::async_trait;
use std::time::Duration;
use redis::{aio::{ConnectionManager, ConnectionManagerConfig}, Script};

use crate::{protocol::*, store::*, AdmissionError as Error, Result};

const READ: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return {'CONFIG'} end
local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)
local value = redis.call('GET', KEYS[2])
return {'OK', value and 'present' or 'absent', value or '', string.format('%.0f', now)}
"#;

// Exact byte comparison avoids u64 rounding in Lua. All fallible validation
// precedes writes; scripting is atomic execution, not rollback on script errors.
const CAS: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 'CONFIG' end
for i = 2, 4 do
    local typ = redis.call('TYPE', KEYS[i]).ok
    local expected = ({'string', 'zset', 'stream'})[i - 1]
    if typ ~= 'none' and typ ~= expected then return 'CORRUPT' end
end
local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)
if ARGV[5] ~= '' and now >= tonumber(ARGV[5]) then return 'RETRY' end
local old = redis.call('GET', KEYS[2])
if ARGV[2] == 'absent' then
    if old then return 'RETRY' end
elseif not old or old ~= ARGV[3] then return 'RETRY' end
redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now)
if ARGV[7] ~= '' then
    if tonumber(ARGV[7]) <= now then return 'RETRY' end
    if not redis.call('ZSCORE', KEYS[3], KEYS[2]) and redis.call('ZCARD', KEYS[3]) >= tonumber(ARGV[8]) then return 'CAPACITY' end
end
if ARGV[6] == '' then redis.call('SET', KEYS[2], ARGV[4])
else redis.call('SET', KEYS[2], ARGV[4], 'PX', ARGV[6]) end
if ARGV[7] == '' then redis.call('ZREM', KEYS[3], KEYS[2])
else redis.call('ZADD', KEYS[3], ARGV[7], KEYS[2]) end
redis.call('XADD', KEYS[4], 'MAXLEN', '~', 10000, '*', 'event', ARGV[9])
return 'OK'
"#;

const BUDGET: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return {'CONFIG'} end
local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)
local count = tonumber(redis.call('GET', KEYS[2]) or '0')
if not count then return {'CORRUPT'} end
if count >= tonumber(ARGV[2]) then
    return {'LIMIT', tostring(math.max(redis.call('PTTL', KEYS[2]), 1))}
end
redis.call('INCR', KEYS[2])
if count == 0 then redis.call('PEXPIRE', KEYS[2], 60000) end
return {'OK', string.format('%.0f', now)}
"#;

const LOAD_MANY: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return {'CONFIG'} end
local out = {'OK', ''}
for i = 2, #KEYS do
    local typ = redis.call('TYPE', KEYS[i]).ok
    if typ ~= 'none' and typ ~= 'string' then return {'CORRUPT'} end
    local value = redis.call('GET', KEYS[i])
    out[#out + 1] = value and 'present' or 'absent'
    out[#out + 1] = value or ''
end
local t = redis.call('TIME')
out[2] = string.format('%.0f', t[1] * 1000 + math.floor(t[2] / 1000))
return out
"#;

// KEYS: policy, audit, records, counters, one key per index write.
// ARGV: policy hash, valid_before, #records, #counters, #indexes, audit event,
// then 5 per record (expected flag, expected, op, value, ttl), 2 per counter
// (delta, limit) and 3 per index write (member, op, score).
// Every check precedes the first write: Lua errors would not roll back.
const COMMIT: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return {'CONFIG'} end
local nr, nc, ni = tonumber(ARGV[3]), tonumber(ARGV[4]), tonumber(ARGV[5])
if #KEYS ~= 2 + nr + nc + ni or #ARGV ~= 6 + 5 * nr + 2 * nc + 3 * ni then return {'CORRUPT'} end
local function kind(key) return redis.call('TYPE', key).ok end
local audit = kind(KEYS[2])
if audit ~= 'none' and audit ~= 'stream' then return {'CORRUPT'} end
for i = 1, nr + nc do
    local typ = kind(KEYS[2 + i])
    if typ ~= 'none' and typ ~= 'string' then return {'CORRUPT'} end
end
for i = 1, ni do
    local typ = kind(KEYS[2 + nr + nc + i])
    if typ ~= 'none' and typ ~= 'zset' then return {'CORRUPT'} end
end
local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)
if ARGV[2] ~= '' and now >= tonumber(ARGV[2]) then return {'RETRY'} end
local a = 7
for i = 1, nr do
    local old = redis.call('GET', KEYS[2 + i])
    if ARGV[a] == 'absent' then
        if old then return {'RETRY'} end
    elseif old ~= ARGV[a + 1] then return {'RETRY'} end
    if ARGV[a + 2] ~= 'keep' and ARGV[a + 2] ~= 'set' and ARGV[a + 2] ~= 'del' then return {'CORRUPT'} end
    a = a + 5
end
local counts = {}
for i = 1, nc do
    local raw = redis.call('GET', KEYS[2 + nr + i]) or '0'
    if not string.match(raw, '^%d+$') or #raw > 9 then return {'CORRUPT'} end
    local delta = tonumber(ARGV[a])
    local value = tonumber(raw) + delta
    if value < 0 then return {'CORRUPT'} end
    if delta > 0 and value > tonumber(ARGV[a + 1]) then return {'LIMIT', tostring(i - 1)} end
    counts[i] = value
    a = a + 2
end
for i = 1, ni do
    local op = ARGV[a + 1]
    if op ~= 'add' and op ~= 'rem' then return {'CORRUPT'} end
    a = a + 3
end
a = 7
for i = 1, nr do
    local key, op = KEYS[2 + i], ARGV[a + 2]
    if op == 'set' then
        if ARGV[a + 4] == '' then redis.call('SET', key, ARGV[a + 3])
        else redis.call('SET', key, ARGV[a + 3], 'PX', ARGV[a + 4]) end
    elseif op == 'del' then redis.call('DEL', key) end
    a = a + 5
end
for i = 1, nc do
    local key = KEYS[2 + nr + i]
    if counts[i] == 0 then redis.call('DEL', key) else redis.call('SET', key, string.format('%d', counts[i])) end
    a = a + 2
end
for i = 1, ni do
    local key = KEYS[2 + nr + nc + i]
    if ARGV[a + 1] == 'add' then redis.call('ZADD', key, ARGV[a + 2], ARGV[a])
    else redis.call('ZREM', key, ARGV[a]) end
    a = a + 3
end
redis.call('XADD', KEYS[2], 'MAXLEN', '~', 10000, '*', 'event', ARGV[6])
return {'OK'}
"#;

const RANGE: &str = r#"
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return {'CONFIG'} end
local typ = redis.call('TYPE', KEYS[2]).ok
if typ ~= 'none' and typ ~= 'zset' then return {'CORRUPT'} end
local t = redis.call('TIME')
local now = string.format('%.0f', t[1] * 1000 + math.floor(t[2] / 1000))
local max = ARGV[2]
if max == 'now' then max = now end
local out = {'OK', now}
for _, member in ipairs(redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', max, 'LIMIT', 0, tonumber(ARGV[3]))) do
    out[#out + 1] = member
end
return out
"#;

#[derive(Clone)]
pub struct RedisAdmissionStore {
    connection: ConnectionManager,
    prefix: String,
    policy: AdmissionPolicy,
    policy_hash: String,
}

impl RedisAdmissionStore {
    pub async fn connect(url: &str, scope: &AdmissionScope, policy: &AdmissionPolicy) -> Result<Self> {
        scope.validate()?;
        policy.validate()?;
        let client = redis::Client::open(url).map_err(|_| Error::StoreUnavailable)?;
        let config = ConnectionManagerConfig::new().set_number_of_retries(1)
            .set_connection_timeout(Duration::from_secs(2)).set_response_timeout(Duration::from_secs(2));
        let mut connection = client.get_connection_manager_with_config(config).await.map_err(|_| Error::StoreUnavailable)?;
        let prefix = format!("admission:{{{}}}", hex::encode(scope.hash().0));
        let policy_hash = hex::encode(policy.hash().0);
        let _: Option<String> = redis::cmd("SET").arg(format!("{prefix}:policy")).arg(&policy_hash).arg("NX")
            .query_async(&mut connection).await.map_err(|_| Error::StoreUnavailable)?;
        let actual: String = redis::cmd("GET").arg(format!("{prefix}:policy")).query_async(&mut connection).await.map_err(|_| Error::StoreUnavailable)?;
        if actual != policy_hash { return Err(Error::ConfigMismatch); }
        Ok(Self { connection, prefix, policy: policy.clone(), policy_hash })
    }
    fn worker_key(&self, key: WorkerKey) -> String { self.key(&StoreKey::Worker(key)) }
    fn key(&self, key: &StoreKey) -> String { format!("{}:{}", self.prefix, key.name()) }
    fn index(&self, index: StoreIndex) -> String { format!("{}:{}", self.prefix, index.name()) }
    pub fn namespace(&self) -> &str { &self.prefix }
}

#[async_trait]
impl AtomicAdmissionStore for RedisAdmissionStore {
    async fn request_budget(&self, key: Option<WorkerKey>) -> Result<u64> {
        let (suffix, limit) = match key {
            Some(key) => (hex::encode(key.0), self.policy.requests_per_key_per_minute),
            None => ("global".into(), self.policy.requests_per_minute),
        };
        let response: Vec<String> = Script::new(BUDGET).key(format!("{}:policy", self.prefix))
            .key(format!("{}:budget:{suffix}", self.prefix)).arg(&self.policy_hash).arg(limit)
            .invoke_async(&mut self.connection.clone()).await.map_err(|_| Error::StoreUnavailable)?;
        match response.first().map(String::as_str) {
            Some("OK") => response.get(1).and_then(|s| s.parse().ok()).ok_or(Error::StateCorrupt),
            Some("CONFIG") => Err(Error::ConfigMismatch),
            Some("LIMIT") => Err(Error::RateLimited { retry_after_ms: response.get(1).and_then(|s| s.parse().ok()).ok_or(Error::StateCorrupt)? }),
            _ => Err(Error::StateCorrupt),
        }
    }
    async fn load(&self, key: WorkerKey) -> Result<Snapshot> {
        let response: Vec<String> = Script::new(READ).key(format!("{}:policy", self.prefix)).key(self.worker_key(key))
            .arg(&self.policy_hash).invoke_async(&mut self.connection.clone()).await.map_err(|_| Error::StoreUnavailable)?;
        if response.first().is_some_and(|s| s == "CONFIG") { return Err(Error::ConfigMismatch); }
        if response.len() != 4 || response[0] != "OK" || !matches!(response[1].as_str(), "present" | "absent") { return Err(Error::StateCorrupt); }
        Ok(Snapshot { raw: (response[1] == "present").then(|| response[2].as_bytes().to_vec()),
            now_ms: response[3].parse().map_err(|_| Error::StateCorrupt)? })
    }
    async fn compare_exchange(&self, key: WorkerKey, write: CasWrite) -> Result<bool> {
        let response: String = Script::new(CAS).key(format!("{}:policy", self.prefix)).key(self.worker_key(key))
            .key(format!("{}:pending", self.prefix)).key(format!("{}:audit", self.prefix))
            .arg(&self.policy_hash).arg(if write.expected.is_some() { "present" } else { "absent" })
            .arg(write.expected.unwrap_or_default()).arg(write.replacement)
            .arg(if write.valid_before_ms == u64::MAX { String::new() } else { write.valid_before_ms.to_string() })
            .arg(write.provisional_ttl_ms.map(|v| v.max(1).to_string()).unwrap_or_default())
            .arg(write.pending_expires_at_ms.map(|v| v.to_string()).unwrap_or_default())
            .arg(self.policy.max_pending_challenges).arg(write.audit_json)
            .invoke_async(&mut self.connection.clone()).await.map_err(|_| Error::StoreUnavailable)?;
        match response.as_str() {
            "OK" => Ok(true), "RETRY" => Ok(false), "CONFIG" => Err(Error::ConfigMismatch),
            "CORRUPT" => Err(Error::StateCorrupt), "CAPACITY" => Err(Error::Capacity), _ => Err(Error::StateCorrupt),
        }
    }
}

fn parse_now(value: Option<&String>) -> Result<u64> { value.and_then(|s| s.parse().ok()).ok_or(Error::StateCorrupt) }

fn script_status(response: &[String]) -> Result<()> {
    match response.first().map(String::as_str) {
        Some("OK") => Ok(()),
        Some("CONFIG") => Err(Error::ConfigMismatch),
        _ => Err(Error::StateCorrupt),
    }
}

#[async_trait]
impl AtomicLeaseStore for RedisAdmissionStore {
    async fn load_many(&self, keys: &[StoreKey]) -> Result<MultiSnapshot> {
        let source = Script::new(LOAD_MANY);
        let mut script = source.prepare_invoke();
        script.key(format!("{}:policy", self.prefix)).arg(&self.policy_hash);
        for key in keys { script.key(self.key(key)); }
        let response: Vec<Vec<u8>> = script.invoke_async(&mut self.connection.clone()).await.map_err(|_| Error::StoreUnavailable)?;
        let text = |i: usize| response.get(i).map(|v| String::from_utf8_lossy(v).into_owned());
        script_status(&[text(0).unwrap_or_default()])?;
        if response.len() != 2 + 2 * keys.len() { return Err(Error::StateCorrupt); }
        let now_ms = parse_now(text(1).as_ref())?;
        let mut values = Vec::with_capacity(keys.len());
        for i in 0..keys.len() {
            match response[2 + 2 * i].as_slice() {
                b"present" => values.push(Some(response[3 + 2 * i].clone())),
                b"absent" => values.push(None),
                _ => return Err(Error::StateCorrupt),
            }
        }
        Ok(MultiSnapshot { values, now_ms })
    }

    async fn commit(&self, transaction: Transaction) -> Result<Commit> {
        let source = Script::new(COMMIT);
        let mut script = source.prepare_invoke();
        script.key(format!("{}:policy", self.prefix)).key(format!("{}:audit", self.prefix));
        for record in &transaction.records { script.key(self.key(&record.key)); }
        for counter in &transaction.counters { script.key(self.key(&counter.key)); }
        for index in &transaction.indexes { script.key(self.index(index.index)); }
        script.arg(&self.policy_hash)
            .arg(if transaction.valid_before_ms == u64::MAX { String::new() } else { transaction.valid_before_ms.to_string() })
            .arg(transaction.records.len()).arg(transaction.counters.len()).arg(transaction.indexes.len())
            .arg(transaction.audit_json);
        for record in transaction.records {
            script.arg(if record.expected.is_some() { "present" } else { "absent" }).arg(record.expected.unwrap_or_default());
            match record.put {
                Put::Keep => script.arg("keep").arg("").arg(""),
                Put::Delete => script.arg("del").arg("").arg(""),
                Put::Set { value, ttl_ms } => script.arg("set").arg(value).arg(ttl_ms.map(|v| v.max(1).to_string()).unwrap_or_default()),
            };
        }
        for counter in transaction.counters { script.arg(counter.delta).arg(counter.limit); }
        for index in transaction.indexes {
            script.arg(index.member.name());
            match index.score { Some(score) => script.arg("add").arg(score), None => script.arg("rem").arg(0) };
        }
        let response: Vec<String> = script.invoke_async(&mut self.connection.clone()).await.map_err(|_| Error::StoreUnavailable)?;
        match response.first().map(String::as_str) {
            Some("OK") => Ok(Commit::Done),
            Some("RETRY") => Ok(Commit::Retry),
            Some("LIMIT") => Ok(Commit::Limit(response.get(1).and_then(|s| s.parse().ok()).ok_or(Error::StateCorrupt)?)),
            Some("CONFIG") => Err(Error::ConfigMismatch),
            _ => Err(Error::StateCorrupt),
        }
    }

    async fn range(&self, index: StoreIndex, max_score: Option<u64>, limit: usize) -> Result<(Vec<StoreKey>, u64)> {
        let response: Vec<String> = Script::new(RANGE).key(format!("{}:policy", self.prefix)).key(self.index(index))
            .arg(&self.policy_hash).arg(match max_score { None => "now".into(), Some(u64::MAX) => "+inf".into(), Some(v) => v.to_string() })
            .arg(limit.max(1)).invoke_async(&mut self.connection.clone()).await.map_err(|_| Error::StoreUnavailable)?;
        script_status(&response)?;
        let now = parse_now(response.get(1))?;
        Ok((response[2..].iter().map(|m| StoreKey::parse(m)).collect::<Result<_>>()?, now))
    }
}
