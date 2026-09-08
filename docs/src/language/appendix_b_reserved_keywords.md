# Appendix B: Reserved Keywords

Lexer keywords and intrinsics (from `psy-lexer` `Token`):

**Keywords:** `const`, `let`, `mut`, `fn`, `struct`, `enum`, `impl`, `trait`, `return`, `if`, `match`, `else`, `while`, `for`, `in`, `where`, `as`, `type`, `extern`, `mod`, `use`, `self`, `crate`, `super`, `pub`

**Intrinsics (also tokenized specially):** `assert`, `assert_eq`, `hash`, `keccak256`, `hash_two_to_one`, and `__…` builtins such as `__secp256k1_verify`, `__emit`, `__invoke_sync`, `__invoke_deferred`

**Type tokens:** `bool`, `Felt`, `u32`, `Array`, `Self`

**Literals:** `true`, `false`
