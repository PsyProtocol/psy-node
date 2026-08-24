//! Psy-lang authoring guidance for agents, distilled from the compiler's own
//! test suite (`psy-compiler-psyprotocol-backup/tests/*.psy`) and stdlib
//! (`psy-std/`). Nothing here is invented: every snippet compiles against the
//! real toolchain (the `#[contract_method]` + `Felt` contract in this module's
//! own integration test was built by `psyup build` end-to-end).
//!
//! Purpose: an agent writing a contract should fetch these BEFORE writing, so
//! the first `psyup_build` has a chance of passing instead of burning rounds
//! on "Unresolved type u64" — the compiler is still the authority, this just
//! narrows the loop.

/// Agent-facing quickstart: what to write, how the flow works.
pub fn agent_instructions() -> &'static str {
    r#"PSY-LANG CONTRACT AUTHORING — QUICKSTART

The language: Psy-lang. A contract is a module of functions; at least one
function must be marked #[contract_method] for the toolchain to discover it.
The compiler (psyup build → dargo) is the authority: write, build, read the
error, fix. Expect 1-3 iterations.

BUILD A CONTRACT (use the psyup_* tools, in order):
  1. psyup_new {name}          — scaffold a project from the official template
  2. write_source {project, path: "src/main.psy", source: <code>}
  3. psyup_build {project}      — compile; fix what it reports; repeat
  4. psyup_deploy {project}     — on-chain (needs the policy to allow
                                  `deploy_contract` and a funded wallet)

TYPES (no u64 — this bites everyone):
  Felt   — the field element / integer type, use for amounts and results
  u32    — small integers; literals like 2u32
  Bool   — true / false
  [T; N] — fixed arrays, e.g. [Felt; 4]
  struct — user types with pub fields

CONTRACT SHAPE:
  #[contract_method]
  fn main() -> Felt {
      42
  }

CORE SYNTAX (all from the compiler test suite):
  let x: Felt = 0;            // immutable binding with type
  let mut y: u32 = 1;         // mutable
  sum += (n as Felt);         // arithmetic + explicit `as` casts
  for n in 0u32..100u32 { }   // ranges, u32 bounds
  if a < b { } else { }
  assert(a < b, "msg");       // panic with message
  assert_eq(a, b, "msg");     // equality check
  return a + b;               // explicit return

ERRORS YOU WILL SEE (and their fixes):
  "Unresolved type u64"        → use Felt or u32
  "add #[contract_method]"     → mark at least one fn with #[contract_method]
  "Unable to discover contract methods" → same fix as above
"#
}

/// Look up one syntax topic. Unknown topics return None.
pub fn get_doc(topic: &str) -> Option<&'static str> {
    let t = topic.trim().to_ascii_lowercase();
    match t.as_str() {
        "types" | "type" | "felt" | "u32" | "bool" => Some(
            "TYPES — Psy-lang has Felt, u32, Bool, arrays [T; N], structs, enums.\n\
             There is NO u64 (compiler rejects it: 'Unresolved type u64').\n\
             Use Felt for amounts/results, u32 for small counters, Bool for flags.\n\
             Literals: 42 (Felt), 2u32 (u32), true/false (Bool).",
        ),
        "contract" | "contract_method" | "method" => Some(
            "#[contract_method] — marks a function as a callable contract method.\n\
             The toolchain discovers methods via this attribute; without it the\n\
             build fails: 'Unable to discover contract methods: add #[contract_method]\n\
             to at least one function'. Put it directly above fn.\n\
             Example:\n\
             \x20 #[contract_method]\n\
             \x20 fn main() -> Felt {\n\
             \x20     42\n\
             \x20 }",
        ),
        "variables" | "let" | "letmut" => Some(
            "VARIABLES —\n\
             \x20 let x: Felt = 0;          // immutable, type annotated\n\
             \x20 let mut y: u32 = 1;       // mutable (required to reassign)\n\
             Reassigning an immutable binding is a compile error.",
        ),
        "control" | "if" | "for" | "loop" => Some(
            "CONTROL FLOW —\n\
             \x20 for n in 0u32..100u32 { sum += (n as Felt); }   // range loop\n\
             \x20 if a < b { } else { }                            // branches\n\
             \x20 return x;                                        // explicit return",
        ),
        "assert" | "assertion" | "assert_eq" => Some(
            "ASSERTS —\n\
             \x20 assert(a < b, \"a != b\");      // panic with message if false\n\
             \x20 assert_eq(b - a, 1, \"msg\");   // equality with message\n\
             Useful for input validation at the top of methods.",
        ),
        "struct" | "structs" | "array" | "arrays" => Some(
            "STRUCTS + ARRAYS —\n\
             \x20 struct Person {\n\
             \x20     pub age: Felt,\n\
             \x20     pub hw: [HW; 2],\n\
             \x20 }\n\
             \x20 let mut arr: [Person; 2] = [person1, person2];\n\
             \x20 arr[0].age = 5;              // field access + mutation\n\
             Constructor: `new TestItem { id: 1, value: 10 }`.",
        ),
        "operators" | "arith" | "math" => Some(
            "OPERATORS — + - * / % (modulo) ** (power), comparisons < <= > >= == !=,\n\
             logical and/or. Type conversions are EXPLICIT: (n as Felt).\n\
             No implicit numeric coercion — cast with `as`.",
        ),
        "storage" | "state" => Some(
            "CONTRACT STATE — the stdlib provides Storage/StorageNew traits\n\
             (psy-std/storage.psy): `pub fn new(offset: Felt, metadata) -> Self`,\n\
             `pub fn read(...)`, `pub fn write(...)`. Use these to persist state\n\
             across calls; plain locals are per-call.",
        ),
        _ => None,
    }
}

/// The list of topics get_doc accepts, for tool descriptions.
pub fn known_topics() -> &'static str {
    "types, contract, variables, control, assert, struct, operators, storage"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instructions_cover_the_traps_agents_hit() {
        let text = agent_instructions();
        assert!(text.contains("u64"), "must warn about u64");
        assert!(text.contains("#[contract_method]"));
        assert!(text.contains("Felt"));
        assert!(text.contains("psyup_build"));
    }

    #[test]
    fn docs_cover_all_known_topics() {
        for t in known_topics().split(',').map(|s| s.trim()) {
            let key = t.split('/').next().unwrap().trim();
            assert!(get_doc(key).is_some(), "topic {key} must resolve");
        }
    }

    #[test]
    fn unknown_topic_is_none_and_case_insensitive() {
        assert!(get_doc("TYPES").is_some());
        assert!(get_doc("  Felt  ").is_some());
        assert!(get_doc("nonsense-topic").is_none());
    }
}
