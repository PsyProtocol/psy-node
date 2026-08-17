//! Structural guards for the R1 rollback module (`psy-memory/rollback/design-r1.md`).
//!
//! These assert properties of the *module graph*, which is the thing being
//! protected and which cannot be expressed as a behavioural test.  That is a
//! different thing from the spike's `include_str!` assertions, which claimed a
//! function body contained a given string and thereby froze "not integrated"
//! into a passing condition.  Nothing here inspects logic; it inspects
//! architecture.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

fn rollback_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src/rollback")
}

fn modules() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for entry in fs::read_dir(rollback_dir()).expect("src/rollback must exist") {
        let path = entry.expect("readable dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("utf8 file stem")
            .to_owned();
        if name == "mod" {
            continue;
        }
        out.insert(name, fs::read_to_string(&path).expect("readable module"));
    }
    out
}

/// Map every `pub` item to the module that defines it.
///
/// Resolving *symbols*, not just module paths, is the whole point: the spike's
/// coupling was `use super::{ BranchExactWriterPrepared, .. }` — a type name
/// re-exported through `mod.rs`.  A guard that only matched module names would
/// have missed exactly the thing it exists to prevent.
fn symbol_owners(modules: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut owners = BTreeMap::new();
    for (module, source) in modules {
        for line in source.lines() {
            let line = line.trim_start();
            let Some(rest) = line.strip_prefix("pub") else {
                continue;
            };
            // `pub fn`, `pub(crate) fn`, `pub(super) fn`, `pub(in path) fn`
            let rest = match rest.strip_prefix('(') {
                Some(after) => match after.find(')') {
                    Some(close) => &after[close + 1..],
                    None => continue,
                },
                None => rest,
            };
            let rest = rest.trim_start();
            // Longest first: `const fn` must not be consumed by the `const` arm.
            for kw in [
                "struct ", "enum ", "trait ", "union ", "type ", "const fn ", "async fn ",
                "unsafe fn ", "const ", "static ", "fn ",
            ] {
                if let Some(name) = rest.strip_prefix(kw) {
                    let name: String = name
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if !name.is_empty() {
                        owners.entry(name).or_insert_with(|| module.clone());
                    }
                    break;
                }
            }
        }
    }
    owners
}

/// Every item a module pulls in via `use super::` / `use crate::rollback::` that
/// cannot be attributed to an `allowed` module.
///
/// Allowlist semantics are deliberate.  An item whose defining module is not
/// present in `src/rollback` — precisely the case for the spike's
/// `BranchExactWriterPrepared` — is unattributable and therefore a violation.
/// Failing open there would reintroduce the exact hole this guard closes.
fn declared_deps(
    source: &str,
    known: &BTreeSet<String>,
    owners: &BTreeMap<String, String>,
    allowed: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut violations = BTreeSet::new();
    for marker in ["use super::", "use crate::rollback::"] {
        let mut rest = source;
        while let Some(at) = rest.find(marker) {
            rest = &rest[at + marker.len()..];
            let end = rest.find(';').unwrap_or(rest.len());
            for token in rest[..end].split(|c: char| !(c.is_alphanumeric() || c == '_')) {
                if token.is_empty() || matches!(token, "self" | "super" | "crate" | "as") {
                    continue;
                }
                if known.contains(token) {
                    if !allowed.contains(token) {
                        violations.insert(format!("module `{token}`"));
                    }
                } else if let Some(owner) = owners.get(token) {
                    if !allowed.contains(owner) {
                        violations.insert(format!("`{token}` (from `{owner}`)"));
                    }
                } else {
                    violations.insert(format!("`{token}` (unresolved)"));
                }
            }
        }
    }
    violations
}

/// design-r1 D8: the typed write core may only depend on identity/key/registry.
///
/// The spike threaded `BranchExactWriterPrepared` through five signatures in
/// `mutation.rs` and `timestamped.rs`, which turned a 586-line write core into
/// a 17-module / 21,399-line dependency closure.
#[test]
fn typed_write_core_depends_only_on_identity_key_registry() {
    let modules = modules();
    let known: BTreeSet<String> = modules.keys().cloned().collect();
    let owners = symbol_owners(&modules);
    let allowed: BTreeSet<String> = ["identity", "key", "registry"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();

    for core in ["mutation", "timestamped"] {
        let Some(source) = modules.get(core) else {
            continue; // not yet ported; the guard arms itself when it lands
        };
        let violations = declared_deps(source, &known, &owners, &allowed);
        assert!(
            violations.is_empty(),
            "design-r1 D8: `{core}` may only depend on {allowed:?}; \
             these `use super::` items are not attributable to an allowed module: {violations:?}"
        );
    }
}

/// The D8 guard is only worth having if it fails on the shape it targets.
/// This exercises the resolver directly, so its correctness does not depend on
/// a violating file happening to exist in the tree.
#[test]
fn d8_guard_rejects_the_spike_coupling_shape() {
    let modules: BTreeMap<String, String> = [
        ("identity", "pub enum ScyllaKeyDomain {}\n"),
        ("registry", "pub const fn key_domain_descriptor() {}\n"),
        ("key", "pub(crate) fn decode_locator_canonical() {}\n"),
        (
            "branch_exact_writer_lifecycle",
            "pub struct BranchExactWriterPrepared;\n",
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect();
    let known: BTreeSet<String> = modules.keys().cloned().collect();
    let owners = symbol_owners(&modules);
    let allowed: BTreeSet<String> = ["identity", "key", "registry"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();

    // `pub`, `pub(crate)` and `pub const fn` must all resolve.
    let clean = "use super::{ScyllaKeyDomain, key_domain_descriptor, decode_locator_canonical};";
    assert!(
        declared_deps(clean, &known, &owners, &allowed).is_empty(),
        "allowed imports must not be flagged"
    );

    // The exact shape that grew the spike's 586-line write core into 21,399 lines.
    let coupled = "use super::{BranchExactWriterPrepared, ScyllaKeyDomain};";
    assert_eq!(
        declared_deps(coupled, &known, &owners, &allowed),
        BTreeSet::from([
            "`BranchExactWriterPrepared` (from `branch_exact_writer_lifecycle`)".to_owned()
        ]),
    );

    // A symbol whose defining module is absent must fail closed, not pass.
    let unknown = "use super::SomeTypeFromAnUnportedModule;";
    assert_eq!(
        declared_deps(unknown, &known, &owners, &allowed),
        BTreeSet::from(["`SomeTypeFromAnUnportedModule` (unresolved)".to_owned()]),
    );
}

/// design-r1 §0.5: the branch-exact coexistence family is out of R1 scope.
#[test]
fn no_branch_exact_or_schema_migration_modules() {
    let forbidden = [
        "branch_exact",
        "cutover",
        "shadow_",
        "dual_write",
        "schema_migration",
        "schema_backfill",
        "schema_deployment",
    ];
    let offenders: Vec<_> = modules()
        .keys()
        .filter(|name| forbidden.iter().any(|f| name.contains(f)))
        .cloned()
        .collect();
    assert!(
        offenders.is_empty(),
        "design-r1 §0.5 cut the branch-exact family from R1; found {offenders:?}"
    );
}

/// design-r1 §11.5: unreachable code does not enter the R1 branch.
///
/// Either wire it up or delete it — `rollback-spike/v1` retains every line.
#[test]
fn no_allow_dead_code_in_rollback_module() {
    let offenders: Vec<_> = modules()
        .iter()
        .filter(|(_, source)| source.contains("allow(dead_code)"))
        .map(|(name, _)| name.clone())
        .collect();
    assert!(
        offenders.is_empty(),
        "design-r1 §11.5 forbids #[allow(dead_code)] in src/rollback; found {offenders:?}"
    );
}

/// design-r1 §11.5: no source-text self-assertions.
///
/// The rule is about `include_str!` aimed at Rust source.  Pulling in a golden
/// vector file is a data fixture and stays allowed; asserting that a `.rs` file
/// contains a given string is what froze "not integrated" into a passing
/// condition in the spike.
#[test]
fn no_include_str_of_rust_source() {
    let mut offenders = Vec::new();
    for (name, source) in modules() {
        let mut rest = source.as_str();
        while let Some(at) = rest.find("include_str!") {
            rest = &rest[at + "include_str!".len()..];
            let end = rest.find(')').unwrap_or(rest.len());
            if rest[..end].contains(".rs") {
                offenders.push(name.clone());
                break;
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "design-r1 §11.5 forbids include_str! of Rust source; found {offenders:?}"
    );
}
