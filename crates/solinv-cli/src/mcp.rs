//! `solinv mcp`: `diff` and `check` for an AI agent, as an MCP server on
//! stdio (JSON-RPC, one message per line).
//!
//! Read-only. A git revision is read with `git archive` into a temporary
//! directory, removed afterwards; the working tree, the index and the
//! stash are never touched. Each tool returns the `--format json` report.

use crate::compare;
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{json, Value};
use solinv_static::diff::Severity;
use solinv_static::json::{self, Compared};
use solinv_static::native::NativeChecks;
use solinv_static::source::SourceKinds;
use std::collections::BTreeSet;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const PROTOCOLS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

const INSTRUCTIONS: &str = "solinv names the account checks (signer, owner, seeds, has_one, constraint, a \
handler's require!) a change to a Solana program removes or widens. After editing an Anchor, Pinocchio or \
native program, call `diff`. A `removed` or `widened` finding is a check the edit dropped: put it back \
unless the user asked for that change, and say which you kept on purpose.";

pub fn serve() -> Result<()> {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(msg) => handle(&msg),
            Err(e) => Some(json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": e.to_string() } })),
        };
        if let Some(reply) = reply {
            writeln!(out, "{reply}")?;
            out.flush()?;
        }
    }
    Ok(())
}

/// The reply to one message; none to a notification.
fn handle(msg: &Value) -> Option<Value> {
    let invalid = |id: Value| Some(json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32600, "message": "invalid request" } }));
    // A batch (gone from MCP since 2025-06-18) or not an object.
    let Some(obj) = msg.as_object() else { return invalid(Value::Null) };
    // A reply to a request: this server sends none.
    if obj.contains_key("result") || obj.contains_key("error") {
        return None;
    }
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") || !obj.get("method").is_some_and(Value::is_string) {
        return invalid(obj.get("id").cloned().unwrap_or(Value::Null));
    }
    let id = msg.get("id")?.clone();
    let params = msg.get("params").cloned().unwrap_or(Value::Null);
    let result = match msg["method"].as_str().unwrap_or_default() {
        "initialize" => {
            let asked = params["protocolVersion"].as_str().unwrap_or_default();
            Ok(json!({
                "protocolVersion": PROTOCOLS.iter().find(|p| **p == asked).unwrap_or(&PROTOCOLS[0]),
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "solinv", "version": env!("CARGO_PKG_VERSION") },
                "instructions": INSTRUCTIONS,
            }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools() })),
        "tools/call" => Ok(call(&params)),
        m => Err((-32601, format!("method not found: {m}"))),
    };
    Some(match result {
        Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
        Err((code, message)) => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }),
    })
}

fn tools() -> Value {
    let path = json!({
        "type": "string",
        "description": "Program source directory, relative to the repository root (e.g. programs/vault/src). \
                        Default: every program found — each programs/<name>/src with #[derive(Accounts)], \
                        and each src with a native or Pinocchio entrypoint"
    });
    let read_only = json!({ "readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false });
    json!([
        {
            "name": "diff",
            "title": "Account checks a change removes",
            "description": "Name the account checks (signer, owner, seeds, has_one, constraint, a handler's \
                require!, a native program's `if !a.is_signer()`) that a change to a Solana program (Anchor, \
                Pinocchio or native) removes or widens. Call it after editing a program. Default: the working \
                tree, uncommitted and untracked edits included, against HEAD. Each finding is `removed`, \
                `widened` (kept as one side of a new `||`) or `warning`, with the instruction, the account, \
                the check, and the source before and after.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "base": { "type": "string", "description": "git revision to compare from. Default HEAD" },
                    "head": { "type": "string", "description": "git revision to compare to. Default: the working tree" },
                    "path": path,
                },
                "additionalProperties": false
            },
            "annotations": read_only,
        },
        {
            "name": "check",
            "title": "Program-wide findings",
            "description": "One version's program-wide findings: signer seeds with no bump, a transfer hook \
                Token-2022 cannot reach or a fallback that skips it, an entry PDA not scoped to the gate it is \
                created under. Default: the working tree.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "rev": { "type": "string", "description": "git revision to read. Default: the working tree" },
                    "path": path,
                },
                "additionalProperties": false
            },
            "annotations": read_only,
        }
    ])
}

/// A tool's result: the report, or what could not be compared with
/// `isError`. A finding is not an error.
fn call(params: &Value) -> Value {
    let args = &params["arguments"];
    let s = |k: &str| args.get(k).and_then(Value::as_str).filter(|v| !v.is_empty()).map(str::to_string);
    let name = params["name"].as_str().unwrap_or_default();
    let report = match name {
        "diff" => diff(s("base").as_deref().unwrap_or("HEAD"), s("head").as_deref(), s("path").as_deref()),
        "check" => check(s("rev").as_deref(), s("path").as_deref()),
        other => Err(anyhow!("unknown tool {other} (diff or check)")),
    };
    let (value, is_error) = match report {
        Ok(v) => (v, false),
        Err(e) => (json::error(name, &format!("{e:#}")), true),
    };
    json!({
        "content": [{ "type": "text", "text": format!("{value:#}") }],
        "structuredContent": value,
        "isError": is_error,
    })
}

/// A tree to read: the working tree, or a revision checked out into a
/// temporary directory.
struct Tree {
    root: PathBuf,
    rev: Option<String>,
    _tmp: Option<Tmp>,
}

impl Tree {
    fn open(repo: &Path, rev: Option<&str>, dirs: &BTreeSet<String>) -> Result<Tree> {
        let Some(rev) = rev else {
            return Ok(Tree { root: repo.to_path_buf(), rev: None, _tmp: None });
        };
        let tmp = Tmp::new(repo)?;
        let present: Vec<&String> = {
            let files = files(repo, Some(rev))?;
            dirs.iter().filter(|d| files.iter().any(|f| f.starts_with(&format!("{d}/")))).collect()
        };
        if !present.is_empty() {
            let mut archive = Command::new("git")
                .current_dir(repo)
                .args(["archive", "--format=tar", rev, "--"])
                .args(&present)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .context("failed to run git")?;
            let untar = Command::new("tar")
                .arg("-xf")
                .arg("-")
                .arg("-C")
                .arg(&tmp.0)
                .stdin(archive.stdout.take().context("git archive: no output")?)
                .status()
                .context("failed to run tar")?;
            let done = archive.wait_with_output()?;
            if !done.status.success() || !untar.success() {
                bail!("git archive {rev}: {}", String::from_utf8_lossy(&done.stderr).trim());
            }
        }
        Ok(Tree { root: tmp.0.clone(), rev: Some(rev.to_string()), _tmp: Some(tmp) })
    }

    fn dir(&self, d: &str) -> PathBuf {
        self.root.join(d)
    }

    /// `d` exists and resolves inside this tree: not a symlink out of it.
    fn holds(&self, d: &str) -> bool {
        match (self.dir(d).canonicalize(), self.root.canonicalize()) {
            (Ok(p), Ok(root)) => p.starts_with(root),
            _ => false,
        }
    }

    fn label(&self, d: &str) -> String {
        match &self.rev {
            Some(r) => format!("{d}@{r}"),
            None => d.to_string(),
        }
    }

    /// A path as read, relative to the repository.
    fn relabel(&self, f: &str) -> Option<String> {
        Path::new(f).strip_prefix(&self.root).ok().map(|p| p.display().to_string())
    }
}

struct Tmp(PathBuf);

impl Tmp {
    /// A new directory of its own under the system's temporary one, which
    /// must not be inside the repository.
    fn new(repo: &Path) -> Result<Tmp> {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let base = std::env::temp_dir().canonicalize().context("no temporary directory")?;
        if base.starts_with(repo.canonicalize()?) {
            bail!("the temporary directory {} is inside the repository: set TMPDIR elsewhere", base.display());
        }
        for _ in 0..16 {
            let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
            let p = base.join(format!(
                "solinv-mcp-{}-{}-{nanos}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            // Not `create_dir_all`: one already there is someone else's.
            // Private to this user: a shared temporary directory without the
            // sticky bit, where another user could swap it, is not defended.
            let mut dir = std::fs::DirBuilder::new();
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut dir, 0o700);
            match dir.create(&p) {
                Ok(()) => return Ok(Tmp(p)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        bail!("could not create a temporary directory under {}", base.display())
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn git(repo: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git").current_dir(repo).args(args).output().context("failed to run git")?;
    if !out.status.success() {
        bail!("git {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The repository the server started in.
fn repo() -> Result<PathBuf> {
    let top = git(Path::new("."), &["rev-parse", "--show-toplevel"])
        .context("solinv mcp reads a git repository: start it in one")?;
    Ok(PathBuf::from(top.trim()))
}

/// A revision, as a commit: a typo is said before anything is read.
fn commit(repo: &Path, rev: &str) -> Result<String> {
    if rev.starts_with('-') {
        bail!("not a revision: {rev}");
    }
    git(repo, &["rev-parse", "--verify", "--quiet", &format!("{rev}^{{commit}}")])
        .map(|_| rev.to_string())
        .map_err(|_| anyhow!("no commit {rev} in this repository"))
}

/// Files in a revision, or in the working tree (untracked ones too).
fn files(repo: &Path, rev: Option<&str>) -> Result<Vec<String>> {
    let out = match rev {
        Some(r) => git(repo, &["ls-tree", "-r", "-z", "--name-only", r])?,
        None => git(repo, &["ls-files", "-z", "--cached", "--others", "--exclude-standard"])?,
    };
    Ok(out.split('\0').filter(|f| !f.is_empty()).map(str::to_string).collect())
}

/// Directories that may hold a program: every `programs/<name>/src`, and
/// every `src`, with a `.rs` file under it. Which are programs is told by
/// reading them.
fn candidates(files: &[String]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for f in files.iter().filter(|f| f.ends_with(".rs")) {
        let parts: Vec<&str> = f.split('/').collect();
        for i in 0..parts.len() - 1 {
            if parts[i] == "src" {
                out.insert(parts[..=i].join("/"));
            }
        }
    }
    out
}

fn is_program(dir: &Path) -> bool {
    dir.is_dir()
        && (SourceKinds::read(dir).is_ok_and(|k| !k.is_empty())
            || NativeChecks::read(dir).is_ok_and(|n| n.has_entrypoint()))
}

/// A `path` argument as a directory under the repository.
fn given(path: &str) -> Result<String> {
    let p = path.trim_start_matches("./").trim_end_matches('/');
    if p.is_empty() || Path::new(p).is_absolute() || p.split('/').any(|c| c == "..") {
        bail!("path must be a directory inside the repository, relative to its root: {path}");
    }
    Ok(p.to_string())
}

fn diff(base: &str, head: Option<&str>, path: Option<&str>) -> Result<Value> {
    let repo = repo()?;
    let base = commit(&repo, base)?;
    let head = head.map(|h| commit(&repo, h)).transpose()?;
    let dirs = match path {
        Some(p) => BTreeSet::from([given(p)?]),
        None => {
            let mut d = candidates(&files(&repo, Some(&base))?);
            d.extend(candidates(&files(&repo, head.as_deref())?));
            d
        }
    };
    let (b, h) = (Tree::open(&repo, Some(&base), &dirs)?, Tree::open(&repo, head.as_deref(), &dirs)?);
    let mut changes = Vec::new();
    let mut compared = Vec::new();
    for d in &dirs {
        let (bd, hd) = (b.dir(d), h.dir(d));
        let outside = |t: &Tree| t.dir(d).exists() && !t.holds(d);
        if outside(&b) || outside(&h) {
            if path.is_some() {
                bail!("{d} leads outside the repository (a symlink): not read");
            }
            continue;
        }
        if !is_program(&bd) {
            if path.is_some() {
                bail!("{d} holds no program at {base}: nothing to compare (call check to read it alone)");
            }
            // New since the base: said, so it is not taken as compared.
            if is_program(&hd) {
                let mode = if SourceKinds::read(&hd).is_ok_and(|k| !k.is_empty()) { "anchor" } else { "native" };
                let note = Some("new since the base: nothing to compare (call check to read it alone)");
                compared.push(Compared { base: None, head: h.label(d), mode, note });
            }
            continue;
        }
        if !hd.exists() {
            // A deleted program takes every check it had. A native one's
            // findings are warnings, so this is too.
            let anchor = SourceKinds::read(&bd).is_ok_and(|k| !k.is_empty());
            let mut c = compare::program_gone(format!("{d} is gone from the head, with every account check it had"), String::new());
            if !anchor {
                c.severity = Severity::Warning;
            }
            changes.push(c);
            compared.push(Compared { base: Some(b.label(d)), head: h.label(d), mode: if anchor { "anchor" } else { "native" }, note: None });
            continue;
        }
        let r = compare::diff_src(&bd, &hd)?;
        if let Some(msg) = r.all_gone {
            changes.push(compare::program_gone(msg.replace(&*b.root.to_string_lossy(), "").replace(&*h.root.to_string_lossy(), ""), String::new()));
        }
        changes.extend(r.changes);
        compared.push(Compared { base: Some(b.label(d)), head: h.label(d), mode: r.mode, note: None });
    }
    if compared.is_empty() {
        bail!(
            "no program found (a programs/<name>/src with #[derive(Accounts)], or a src with a native \
             entrypoint) that is in {base}: pass path"
        );
    }
    let relabel = |f: &str| b.relabel(f).or_else(|| h.relabel(f)).unwrap_or_else(|| f.to_string());
    Ok(json::report("diff", &compared, &changes, &relabel))
}

fn check(rev: Option<&str>, path: Option<&str>) -> Result<Value> {
    let repo = repo()?;
    let rev = rev.map(|r| commit(&repo, r)).transpose()?;
    let dirs = match path {
        Some(p) => BTreeSet::from([given(p)?]),
        None => candidates(&files(&repo, rev.as_deref())?),
    };
    let t = Tree::open(&repo, rev.as_deref(), &dirs)?;
    let mut changes = Vec::new();
    let mut compared = Vec::new();
    for d in &dirs {
        let td = t.dir(d);
        if td.exists() && !t.holds(d) {
            if path.is_some() {
                bail!("{d} leads outside the repository (a symlink): not read");
            }
            continue;
        }
        if path.is_none() && !is_program(&td) {
            continue;
        }
        let (c, mode) = compare::check_src(&td)?;
        changes.extend(c);
        compared.push(Compared { base: None, head: t.label(d), mode, note: None });
    }
    if compared.is_empty() {
        bail!("no program found (a programs/<name>/src with #[derive(Accounts)], or a src with a native entrypoint): pass path");
    }
    let relabel = |f: &str| t.relabel(f).unwrap_or_else(|| f.to_string());
    Ok(json::report("check", &compared, &changes, &relabel))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_are_src_dirs_with_rust_under_them() {
        let files = ["programs/vault/src/lib.rs", "programs/vault/src/ix/mod.rs", "src/main.rs", "README.md", "app/src/index.ts"]
            .map(String::from);
        assert_eq!(candidates(&files), BTreeSet::from(["programs/vault/src".to_string(), "src".to_string()]));
    }

    #[test]
    fn a_path_outside_the_repository_is_refused() {
        assert!(given("../x").is_err());
        assert!(given("/etc").is_err());
        assert_eq!(given("./programs/v/src/").unwrap(), "programs/v/src");
    }

    #[test]
    fn notifications_get_no_reply_and_unknown_methods_an_error() {
        assert!(handle(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })).is_none());
        assert_eq!(handle(&json!([])).unwrap()["error"]["code"], -32600);
        assert_eq!(handle(&json!({ "jsonrpc": "2.0", "id": 9 })).unwrap()["error"]["code"], -32600);
        assert_eq!(handle(&json!({ "jsonrpc": "1.0", "id": 9, "method": "ping" })).unwrap()["error"]["code"], -32600);
        assert!(handle(&json!({ "jsonrpc": "2.0", "id": 9, "result": {} })).is_none());
        let r = handle(&json!({ "jsonrpc": "2.0", "id": 1, "method": "resources/list" })).unwrap();
        assert_eq!(r["error"]["code"], -32601);
        let r = handle(&json!({ "jsonrpc": "2.0", "id": 2, "method": "initialize", "params": { "protocolVersion": "2025-03-26" } })).unwrap();
        assert_eq!(r["result"]["protocolVersion"], "2025-03-26");
        let r = handle(&json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list" })).unwrap();
        let names: Vec<&str> = r["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["diff", "check"]);
    }
}
