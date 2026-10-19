use std::{cell::Cell, collections::BTreeMap, fmt, fs::File, io::{self, BufReader, Read}, path::PathBuf};
use clap::Args;
use serde::{de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor}, Deserialize, Deserializer, Serialize};

#[derive(Args)]
pub struct InspectAnvilStateArgs {
    #[arg(long)]
    state: PathBuf,
    #[arg(long)]
    fork: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Genesis {
    timestamp: String,
    header: BTreeMap<String, String>,
    #[serde(rename = "block1ParentHash", skip_serializing_if = "Option::is_none")]
    block1_parent_hash: Option<String>,
}

// Guards apply before serde can grow its scratch buffers. Ignored payloads
// have no byte limit, but all JSON containers share a structural depth limit.
const MAX_JSON_DEPTH: usize = 128;
struct GuardedRead<'a, R> {
    inner: R,
    budget: &'a Cell<Option<usize>>,
    depth: usize,
    in_string: bool,
    escaped: bool,
}
impl<R: Read> Read for GuardedRead<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() { return Ok(0); }
        if self.budget.get() == Some(0) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Anvil metadata exceeds bounded read budget"));
        }
        let limit = self.budget.get().unwrap_or(out.len()).min(out.len());
        let n = self.inner.read(&mut out[..limit])?;
        if let Some(left) = self.budget.get() { self.budget.set(Some(left - n)); }
        for &byte in &out[..n] {
            if self.in_string {
                if self.escaped { self.escaped = false; }
                else if byte == b'\\' { self.escaped = true; }
                else if byte == b'"' { self.in_string = false; }
            } else {
                match byte {
                    b'"' => self.in_string = true,
                    b'[' | b'{' => {
                        if self.depth == MAX_JSON_DEPTH {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, "Anvil JSON exceeds structural depth limit"));
                        }
                        self.depth += 1;
                    }
                    b']' | b'}' => self.depth = self.depth.saturating_sub(1),
                    _ => {}
                }
            }
        }
        Ok(n)
    }
}

fn next_key<'de, M: MapAccess<'de>>(map: &mut M, budget: &Cell<Option<usize>>) -> Result<Option<String>, M::Error> {
    let outer = budget.get();
    let limit = outer.unwrap_or(1024).min(1024);
    budget.set(Some(limit));
    let key = map.next_key();
    let consumed = limit - budget.get().unwrap();
    budget.set(match outer {
        Some(left) => Some(left.checked_sub(consumed).ok_or_else(|| de::Error::custom("Anvil metadata read budget exhausted"))?),
        None => None,
    });
    key
}

struct Header<'a>(&'a Cell<Option<usize>>);
impl<'de> DeserializeSeed<'de> for Header<'_> {
    type Value = BTreeMap<String, String>;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        struct Fields<'a>(&'a Cell<Option<usize>>);
        impl<'de> Visitor<'de> for Fields<'_> {
            type Value = BTreeMap<String, String>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("a string-valued Anvil header object") }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut header = BTreeMap::new();
                while let Some(key) = next_key(&mut map, self.0)? {
                    if header.contains_key(&key) { return Err(de::Error::custom("duplicate header field")); }
                    header.insert(key, map.next_value::<String>()?);
                }
                if !header.contains_key("number") || !header.contains_key("timestamp") {
                    return Err(de::Error::custom("header is missing number or timestamp"));
                }
                Ok(header)
            }
        }
        self.0.set(Some(64 * 1024));
        let result = d.deserialize_map(Fields(self.0));
        self.0.set(None);
        result
    }
}

struct BlockMetadata {
    number: String,
    timestamp: String,
    parent_hash: Option<String>,
}
struct Block<'a> {
    budget: &'a Cell<Option<usize>>,
    genesis: &'a mut Option<BTreeMap<String, String>>,
}
impl<'de> DeserializeSeed<'de> for Block<'_> {
    type Value = BlockMetadata;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        impl<'de> Visitor<'de> for Block<'_> {
            type Value = BlockMetadata;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("an Anvil block object") }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut header = None;
                while let Some(key) = next_key(&mut map, self.budget)? {
                    if key == "header" {
                        if header.is_some() { return Err(de::Error::custom("duplicate block header")); }
                        let mut fields = map.next_value_seed(Header(self.budget))?;
                        let number = quantity(&fields["number"]).ok_or_else(|| de::Error::custom("block number must be a hex quantity"))?.trim_start_matches('0');
                        header = Some(if number.is_empty() {
                            if self.genesis.is_some() { return Err(de::Error::custom("2 block 0 headers; refusing to select or drop one")); }
                            let metadata = BlockMetadata {
                                number: fields["number"].clone(),
                                timestamp: fields["timestamp"].clone(),
                                parent_hash: fields.get("parentHash").cloned(),
                            };
                            *self.genesis = Some(fields);
                            metadata
                        } else {
                            BlockMetadata {
                                number: fields.remove("number").unwrap(),
                                timestamp: fields.remove("timestamp").unwrap(),
                                parent_hash: fields.remove("parentHash"),
                            }
                        });
                    } else { map.next_value::<IgnoredAny>()?; }
                }
                header.ok_or_else(|| de::Error::custom("block without a header object"))
            }
        }
        d.deserialize_map(self)
    }
}

fn quantity(value: &str) -> Option<&str> {
    value.strip_prefix("0x").filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_hexdigit()))
}
struct Blocks<'a>(&'a Cell<Option<usize>>);
impl<'de> DeserializeSeed<'de> for Blocks<'_> {
    type Value = Genesis;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Genesis, D::Error> {
        impl<'de> Visitor<'de> for Blocks<'_> {
            type Value = Genesis;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("an Anvil blocks array") }
            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Genesis, S::Error> {
                let mut genesis = None;
                let mut parent: Option<String> = None;
                let mut genesis_timestamp = None;
                while let Some(block) = seq.next_element_seed(Block { budget: self.0, genesis: &mut genesis })? {
                    let number = quantity(&block.number).unwrap().trim_start_matches('0');
                    if number.is_empty() {
                        genesis_timestamp = Some(block.timestamp);
                    } else if number == "1" {
                        let hash = block.parent_hash.as_ref().filter(|h| h.len() == 66 && quantity(h).is_some())
                            .ok_or_else(|| de::Error::custom("block 1 parentHash must be a 32-byte hash"))?.to_ascii_lowercase();
                        if parent.as_ref().is_some_and(|p| p != &hash) { return Err(de::Error::custom("conflicting block 1 parentHash values")); }
                        parent = Some(hash);
                    }
                }
                let header = genesis.ok_or_else(|| de::Error::custom("0 block 0 headers; refusing to bind genesis"))?;
                let genesis_timestamp = genesis_timestamp.unwrap();
                let digits = quantity(&genesis_timestamp).ok_or_else(|| de::Error::custom("genesis timestamp must be a hex quantity"))?.trim_start_matches('0');
                let timestamp = if digits.is_empty() { 0 } else {
                    u64::from_str_radix(digits, 16).map_err(|_| de::Error::custom("genesis timestamp does not fit Anvil --timestamp"))?
                };
                Ok(Genesis { timestamp: timestamp.to_string(), header, block1_parent_hash: parent })
            }
        }
        d.deserialize_seq(self)
    }
}

struct Snapshot<'a>(&'a Cell<Option<usize>>);
impl<'de> DeserializeSeed<'de> for Snapshot<'_> {
    type Value = Genesis;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Genesis, D::Error> {
        impl<'de> Visitor<'de> for Snapshot<'_> {
            type Value = Genesis;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("an Anvil state object") }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Genesis, M::Error> {
                let mut genesis = None;
                while let Some(key) = next_key(&mut map, self.0)? {
                    if key == "blocks" {
                        if genesis.is_some() { return Err(de::Error::custom("duplicate blocks key")); }
                        genesis = Some(map.next_value_seed(Blocks(self.0))?);
                    } else { map.next_value::<IgnoredAny>()?; }
                }
                genesis.ok_or_else(|| de::Error::custom("Anvil state has no blocks array"))
            }
        }
        d.deserialize_map(self)
    }
}

fn inspect(reader: impl Read, fork: bool) -> serde_json::Result<Option<Genesis>> {
    let budget = Cell::new(None);
    // Guard must be OUTSIDE BufReader: serde reads one byte at a time and must
    // not prefetch metadata bytes while the budget is disabled.
    let reader = GuardedRead { inner: reader, budget: &budget, depth: 0, in_string: false, escaped: false };
    let mut deserializer = serde_json::Deserializer::from_reader(reader);
    let result = if fork { IgnoredAny::deserialize(&mut deserializer)?; None }
        else { Some(Snapshot(&budget).deserialize(&mut deserializer)?) };
    deserializer.end()?;
    Ok(result)
}

pub fn run(args: InspectAnvilStateArgs) -> anyhow::Result<()> {
    let reader = BufReader::with_capacity(8 * 1024 * 1024, File::open(args.state)?);
    let genesis = inspect(reader, args.fork)?;
    println!("{}", serde_json::to_string(&genesis)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = r#"{"number":"0x0","timestamp":"0x000a","extra":"\u0061"}"#;
    fn snapshot() -> String { format!(r#"{{"blocks":[{{"header":{HEADER}}}]}}"#) }
    struct Chunks<'a> { bytes: &'a [u8], size: usize }
    impl Read for Chunks<'_> {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let n = self.size.min(out.len()).min(self.bytes.len());
            out[..n].copy_from_slice(&self.bytes[..n]);
            self.bytes = &self.bytes[n..];
            Ok(n)
        }
    }
    fn parse(text: &str, fork: bool, size: usize) -> serde_json::Result<Option<Genesis>> {
        inspect(BufReader::with_capacity(size, Chunks { bytes: text.as_bytes(), size }), fork)
    }

    #[test]
    fn preserves_headers_across_chunk_boundaries() {
        for size in [1, 2, 3, 7, 64] {
            let genesis = parse(&snapshot(), false, size).unwrap().unwrap();
            assert_eq!(genesis.timestamp, "10");
            assert_eq!(genesis.header["extra"], "a");
            assert!(genesis.block1_parent_hash.is_none());
        }
    }

    #[test]
    fn validates_the_entire_document_and_ignored_payloads() {
        let good = snapshot();
        for end in 0..good.len() { assert!(parse(&good[..end], false, 3).is_err()); }
        for tail in ["x", "{}", " null", ","] { assert!(parse(&(good.clone() + tail), false, 3).is_err()); }
        assert!(parse(&(good + " \r\n\t"), false, 1).is_ok());
        for bad in [r#"{"x":"\q"}"#, r#"{"x":[1,]}"#, r#"{"x":01}"#, r#"{"x":1e}"#, r#"{"x":true"#] {
            assert!(parse(bad, true, 1).is_err());
        }
        let huge = format!(r#"{{"accounts":{{"code":"{}"}},"blocks":[{{"header":{HEADER}}}],"tail":[true,null,1e999]}}"#, "x".repeat(2 * 1024 * 1024));
        assert!(parse(&huge, false, 7).is_ok());
        assert!(parse(&(huge + "!"), false, 7).is_err());
        for tail in [r#""\q""#, "[1,]", "01", "1e", "{\"x\":"] {
            let invalid = format!(r#"{{"blocks":[{{"header":{HEADER}}}],"ignored":{tail}}}"#);
            assert!(parse(&invalid, false, 1).is_err());
        }
        assert!(parse(r#"{"blocks":[]}"#, true, 1).unwrap().is_none());
        assert!(parse(r#"{"blocks":[]}"#, false, 1).is_err());
    }

    #[test]
    fn rejects_ambiguous_or_invalid_chain_metadata() {
        for blocks in [
            format!(r#"{{"header":{HEADER}}},{{"header":{HEADER}}}"#),
            r#"{"header":{"number":"0x0","timestamp":"0x10000000000000000"}}"#.into(),
            r#"{"header":{"number":"0x0","timestamp":"0x1","extra":2}}"#.into(),
            r#"{"header":{"number":"0xz","timestamp":"0x1"}}"#.into(),
            r#"{"header":{"number":"0x0"}}"#.into(),
            r#"{}"#.into(),
            format!(r#"{{"header":{HEADER},"header":{HEADER}}}"#),
            r#"{"header":{"number":"0x0","number":"0x0","timestamp":"0x1"}}"#.into(),
        ] { assert!(parse(&format!(r#"{{"blocks":[{blocks}]}}"#), false, 2).is_err()); }
        assert!(parse(&format!(r#"{{"blocks":[{{"header":{HEADER}}}],"blocks":[]}}"#), false, 1).is_err());
        let parent = "ab".repeat(32);
        let block1 = format!(r#"{{"header":{{"number":"0x01","timestamp":"0x2","parentHash":"0x{parent}"}}}}"#);
        let good = format!(r#"{{"blocks":[{block1},{{"header":{HEADER}}},{block1}]}}"#);
        assert_eq!(parse(&good, false, 3).unwrap().unwrap().block1_parent_hash.unwrap(), format!("0x{parent}"));
        let serialized = serde_json::to_value(parse(&good, false, 3).unwrap().unwrap()).unwrap();
        assert_eq!(serialized["block1ParentHash"], format!("0x{parent}"));
        let conflict = good.replacen(&parent, &"cd".repeat(32), 1);
        assert!(parse(&conflict, false, 3).is_err());
        assert!(parse(&good.replace(&parent, "00"), false, 3).is_err());
    }

    #[test]
    fn bounds_ignored_structural_depth_in_both_modes() {
        let nested = format!("{}null{}", "[".repeat(MAX_JSON_DEPTH + 1), "]".repeat(MAX_JSON_DEPTH + 1));
        let objects = format!("{}null{}", "{\"x\":".repeat(MAX_JSON_DEPTH + 1), "}".repeat(MAX_JSON_DEPTH + 1));
        for value in [nested, objects] {
            for text in [
                format!(r#"{{"ignored":{value},"blocks":[{{"header":{HEADER}}}]}}"#),
                format!(r#"{{"blocks":[{{"header":{HEADER},"ignored":{value}}}]}}"#),
            ] {
                for fork in [false, true] {
                    for size in [1, 7, 1024] {
                        let error = parse(&text, fork, size).unwrap_err().to_string();
                        assert!(error.contains("structural depth limit"), "{error}");
                    }
                }
            }
        }
        let flat = format!(r#"{{"ignored":"{}","blocks":[{{"header":{HEADER}}}]}}"#, r#"[{\"\\\"}]"#.repeat(256 * 1024));
        for fork in [false, true] { assert!(parse(&flat, fork, 7).is_ok()); }
    }

    #[test]
    fn bounds_materialized_metadata_but_not_skipped_values() {
        let large_key = format!(r#"{{"{}":null,"blocks":[{{"header":{HEADER}}}]}}"#, "k".repeat(2048));
        assert!(parse(&large_key, false, 3).is_err());
        let large_header = format!(r#"{{"blocks":[{{"header":{{"number":"0x0","timestamp":"0x1","extra":"{}"}}}}]}}"#, "x".repeat(65536));
        assert!(parse(&large_header, false, 3).is_err());
        let mut fields = BTreeMap::new();
        fields.insert("number".to_string(), "0x0".to_string());
        fields.insert("timestamp".to_string(), "0x1".to_string());
        for index in 0..10000 { fields.insert(format!("k{index}"), "v".to_string()); }
        let many_keys = serde_json::json!({"blocks": [{"header": fields}]}).to_string();
        assert!(parse(&many_keys, false, 7).is_err());
    }
}
