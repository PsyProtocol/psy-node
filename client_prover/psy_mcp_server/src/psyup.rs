//! psyup integration — let the agent scaffold, write and BUILD Psy-lang
//! contracts through the installed PSY toolchain (`psyup new/build`), and let
//! the OWNER deploy them (`psyup deploy`, owner-gated, signing with the loaded
//! wallet).
//!
//! Why subprocess and not a re-implementation: `psyup` already IS the
//! write→compile→deploy chain (`dargo compile`, `psy_user_cli deploy-contract`
//! with auto-filled rpc-config/contract-path). Wrapping it keeps the tools
//! honest — the same compiler the humans use, the same deploy path — and the
//! only new surface here is the validation around the subprocess boundary.
//!
//! The one judgement call: DEPLOY is owner-only. `psy_user_cli` signs with a
//! PRIVATE_KEY env var; we hand it the loaded wallet's own key, so a deployed
//! contract is paid for by THIS wallet and only by the owner's explicit action.
//! An agent can iterate on code freely; it cannot put code on chain by itself.

use std::path::{Component, Path, PathBuf};
use std::process::Command;

/// Max bytes of combined stdout+stderr returned to the caller. Compilers can
/// be chatty; the tail is what the agent fixes against.
const OUTPUT_CAP: usize = 16 * 1024;

/// A project name is a single path component of letters, digits, `_`, `-`.
/// Anything else (slashes, dots, spaces, shell metacharacters) is rejected
/// BEFORE it can reach the subprocess boundary — the tool must never hand a
/// caller-controlled string to a shell.
pub fn valid_project_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Root directory all contract projects live under.
/// `PSY_MCP_CONTRACTS_ROOT` env, else `$HOME/psy-mcp-contracts`.
pub fn contracts_root() -> Result<PathBuf, String> {
    if let Ok(root) = std::env::var("PSY_MCP_CONTRACTS_ROOT") {
        if !root.trim().is_empty() {
            return Ok(PathBuf::from(root.trim()));
        }
    }
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    Ok(PathBuf::from(home).join("psy-mcp-contracts"))
}

/// Resolve a validated project name to its directory under the root.
/// Callers then check existence themselves (`new` needs it absent,
/// build/deploy/write need it present).
pub fn project_dir(root: &Path, name: &str) -> Result<PathBuf, String> {
    if !valid_project_name(name) {
        return Err(format!(
            "invalid project name `{name}` — use letters, digits, `_` or `-` only"
        ));
    }
    Ok(root.join(name))
}

/// Locate the directory that actually contains the contract source.
///
/// `psyup new` scaffolds a dapp-style project (`<name>/` with a frontend and a
/// `<name>/contract/` sub-project), so Dargo.toml is NOT at the project root.
/// Search the project root and its direct children for Dargo.toml — the agent
/// writes source and the tools build/deploy from wherever it actually lives.
pub fn find_contract_dir(project: &Path) -> Result<PathBuf, String> {
    for candidate in [project.to_path_buf(), project.join("contract"), project.join("src")] {
        if candidate.join("Dargo.toml").is_file() {
            return Ok(candidate);
        }
    }
    Err(format!(
        "no Dargo.toml under {} — create the project with psyup_new first",
        project.display()
    ))
}

/// The psyup binary to invoke. `PSYUP_BIN` env, else `$HOME/.psy/bin/psyup`.
pub fn psyup_bin() -> Result<PathBuf, String> {
    if let Ok(bin) = std::env::var("PSYUP_BIN") {
        if !bin.trim().is_empty() {
            return Ok(PathBuf::from(bin.trim()));
        }
    }
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    Ok(PathBuf::from(home).join(".psy/bin/psyup"))
}

/// A file path INSIDE a project, for `write_source`.
///
/// The caller supplies a relative path; we resolve it and refuse anything
/// that escapes the project directory. A `..` or absolute path is a hard
/// error, not a silent clamp — the agent should hear that it tried to write
/// outside its project rather than have the write land somewhere surprising.
pub fn safe_project_file(project: &Path, rel: &str) -> Result<PathBuf, String> {
    let rel = rel.trim();
    if rel.is_empty() {
        return Err("empty file path".to_string());
    }
    let candidate = Path::new(rel);
    if candidate.is_absolute() {
        return Err(format!("absolute paths are not allowed: `{rel}`"));
    }
    let mut out = project.to_path_buf();
    for comp in candidate.components() {
        match comp {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(format!("path escapes the project directory: `{rel}`"))
            }
            _ => return Err(format!("unsupported path component in `{rel}`")),
        }
    }
    // Must stay strictly inside the project root.
    if !out.starts_with(project) {
        return Err(format!("path escapes the project directory: `{rel}`"));
    }
    Ok(out)
}

/// Run psyup with `args` in `cwd`, optionally adding env vars (used for
/// PRIVATE_KEY on deploy). Returns the combined stdout+stderr, tail-capped.
pub fn run_psyup(
    args: &[&str],
    cwd: &Path,
    extra_env: &[(&str, String)],
) -> Result<(bool, String), String> {
    let bin = psyup_bin()?;
    if !bin.exists() {
        return Err(format!(
            "psyup not found at {} — install the toolchain first (`psyup install`), \
             or set PSYUP_BIN",
            bin.display()
        ));
    }
    let mut cmd = Command::new(&bin);
    cmd.args(args).current_dir(cwd);
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let output = cmd
        .output()
        .map_err(|e| format!("failed to run {}: {e}", bin.display()))?;
    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    if text.len() > OUTPUT_CAP {
        text = format!("…(truncated, {} bytes)…\n{}", text.len(), &text[text.len() - OUTPUT_CAP..]);
    }
    Ok((output.status.success(), text.trim_end().to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_names_are_strictly_validated() {
        for good in ["demo", "my-contract", "a_b", "C1", "-x", "x-"] {
            assert!(valid_project_name(good), "should accept {good}");
        }
        for bad in ["a/b", ".", "..", "a b", "a;rm", "$(x)", "a.b", "", "a\x00b", "x".repeat(65).as_str()] {
            assert!(!valid_project_name(bad), "should reject {bad:?}");
        }
    }

    #[test]
    fn find_contract_dir_handles_dapp_layout() {
        let root = std::env::temp_dir().join("psyup-test-dapp");
        std::fs::create_dir_all(root.join("contract")).unwrap();
        std::fs::write(root.join("contract/Dargo.toml"), "name = \"x\"\n").unwrap();
        assert_eq!(
            find_contract_dir(&root).unwrap(),
            root.join("contract")
        );
        // Flat layout (project root has Dargo.toml) also works.
        std::fs::write(root.join("Dargo.toml"), "name = \"x\"\n").unwrap();
        assert_eq!(find_contract_dir(&root).unwrap(), root);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn safe_project_file_blocks_escapes() {
        let root = PathBuf::from("/contracts/demo");
        assert_eq!(
            safe_project_file(&root, "src/main.psy").unwrap(),
            PathBuf::from("/contracts/demo/src/main.psy")
        );
        assert_eq!(safe_project_file(&root, "./Dargo.toml").unwrap(), root.join("Dargo.toml"));
        for evil in ["../escape.psy", "a/../../escape.psy", "/etc/passwd", "..", "a/.."] {
            assert!(safe_project_file(&root, evil).is_err(), "should block {evil:?}");
        }
    }
}
