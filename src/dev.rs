//! Finds development servers left running after the work on them stopped.
//!
//! These are usually idle, so they never show up as CPU hogs, and once macOS
//! has pushed them into swap their resident size looks tiny. What gives them
//! away is their shape rather than their load: a JavaScript runtime started
//! from a project folder whose terminal is gone, that runs the same command
//! more than once, or that has simply been up for over a week.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use crate::scan::{DAY, Finding, Kill, MANAGED_PREFIXES, Proc, Severity, Snapshot, dur, size};

/// Orphaned or duplicated sessions younger than this may still be in use.
const STALE_AGE: u64 = DAY;
/// Nobody keeps a dev server they are using up this long.
const ANCIENT_AGE: u64 = 7 * DAY;

const RUNTIMES: [&str; 8] = [
    "bun", "bun.native", "node", "deno", "workerd", "tsx", "esbuild", "npm",
];

/// A user-owned JavaScript runtime, or a binary shipped inside node_modules.
pub(crate) fn is_runtime(p: &Proc, uid: u32) -> bool {
    p.uid == uid
        && !MANAGED_PREFIXES.iter().any(|m| p.path.starts_with(m))
        && (RUNTIMES.contains(&base(&p.path)) || p.path.contains("/node_modules/"))
}

/// The project a process was started from, judged by its arguments alone: the
/// folder holding the `node_modules` they point into.
pub(crate) fn modules_project(args: &str, home: &str) -> Option<String> {
    args.split_whitespace().find_map(|token| {
        let root = &token[..token.find("/node_modules/")?];
        project_dir(root, home)
    })
}

/// Scratch folders: nothing started there is meant to outlive the task.
const TEMP_PREFIXES: [&str; 3] = ["/tmp/", "/private/tmp/", "/private/var/folders/"];

/// Only real folders under the home directory count: hidden ones hold tool
/// caches (npx, bunx) and global installs, and `~` itself is no project.
/// Temporary folders count too.
fn project_dir(dir: &str, home: &str) -> Option<String> {
    if TEMP_PREFIXES.iter().any(|t| dir.starts_with(t)) {
        return Some(dir.trim_end_matches('/').to_string());
    }
    let rel = dir.strip_prefix(home)?.strip_prefix('/')?.trim_end_matches('/');
    let real = !rel.is_empty() && !rel.split('/').any(|part| part.starts_with('.'));
    real.then(|| format!("{home}/{rel}"))
}

struct Session<'a> {
    root: &'a Proc,
    orphaned: bool,
    duplicate: bool,
}

pub(crate) fn find(snap: &Snapshot) -> Vec<Finding> {
    let mut children: HashMap<u32, Vec<&Proc>> = HashMap::new();
    for p in &snap.procs {
        children.entry(p.ppid).or_default().push(p);
    }

    let project_of: HashMap<u32, String> = snap
        .procs
        .iter()
        .filter(|p| is_runtime(p, snap.uid))
        .filter_map(|p| {
            let project = modules_project(&p.args, &snap.home).or_else(|| {
                project_dir(snap.cwds.get(&p.pid)?, &snap.home)
            })?;
            Some((p.pid, project))
        })
        .collect();

    // A session starts at the topmost process of a project: launchers like
    // `bun run dev` and the servers they start belong together.
    let mut roots: BTreeMap<&str, Vec<&Proc>> = BTreeMap::new();
    for p in &snap.procs {
        let Some(project) = project_of.get(&p.pid) else { continue };
        if project_of.get(&p.ppid) != Some(project) {
            roots.entry(project).or_default().push(p);
        }
    }

    let mut findings = Vec::new();
    for (project, roots) in roots {
        let mut by_command: HashMap<String, Vec<&Proc>> = HashMap::new();
        for root in &roots {
            by_command.entry(command_key(&root.args)).or_default().push(root);
        }

        let stale: Vec<Session> = roots
            .iter()
            .filter_map(|&root| {
                let same = &by_command[&command_key(&root.args)];
                let newest = same.iter().map(|p| p.run_secs).min().unwrap_or(0);
                let old = root.run_secs >= STALE_AGE;
                let orphaned = old && root.ppid == 1;
                let duplicate = old && same.len() > 1 && root.run_secs > newest;
                let ancient = root.run_secs >= ANCIENT_AGE;
                (orphaned || duplicate || ancient).then_some(Session { root, orphaned, duplicate })
            })
            .collect();
        if stale.is_empty() {
            continue;
        }
        findings.push(finding(project, &stale, &children, snap));
    }
    findings
}

fn finding(
    project: &str,
    sessions: &[Session],
    children: &HashMap<u32, Vec<&Proc>>,
    snap: &Snapshot,
) -> Finding {
    // Parents go first when stopping: a watcher whose child dies first just
    // starts it again.
    let mut pids = Vec::new();
    let mut seen = HashSet::new();
    let mut memory = 0;
    for session in sessions {
        let mut todo = vec![session.root];
        while let Some(p) = todo.pop() {
            if !seen.insert(p.pid) {
                continue;
            }
            pids.push(p.pid);
            memory += p.mem;
            todo.extend(children.get(&p.pid).into_iter().flatten().rev());
        }
    }

    let mut commands: Vec<(String, usize)> = Vec::new();
    for session in sessions {
        let label = command_label(&session.root.args);
        match commands.iter_mut().find(|(l, _)| *l == label) {
            Some((_, n)) => *n += 1,
            None => commands.push((label, 1)),
        }
    }
    let commands = commands
        .iter()
        .map(|(label, n)| if *n > 1 { format!("{n}× {label}") } else { label.clone() })
        .collect::<Vec<_>>()
        .join(", ");
    let oldest = sessions.iter().map(|s| s.root.run_secs).max().unwrap_or(0);

    let reason = if sessions.iter().any(|s| s.orphaned) {
        "The terminal that started them is gone, so nothing will ever stop them."
    } else if sessions.iter().any(|s| s.duplicate) {
        "The same command is running more than once."
    } else {
        "They have been running for over a week."
    };
    let shown = match project.strip_prefix(&snap.home) {
        Some(rel) => format!("~{rel}"),
        None => project.to_string(),
    };
    let count = sessions.len();

    Finding {
        severity: Severity::Warn,
        key: format!("dev:{project}"),
        title: format!(
            "Forgotten {} in {shown}",
            if count > 1 { "dev servers" } else { "dev server" }
        ),
        detail: format!(
            "{commands} · {} using {} · oldest started {} ago",
            match pids.len() {
                1 => "1 process".to_string(),
                n => format!("{n} processes"),
            },
            size(memory),
            dur(oldest)
        ),
        hint: format!("{reason} Stop them unless you are working on this project."),
        processes: {
            let procs: Vec<&Proc> = snap.procs.iter().filter(|p| seen.contains(&p.pid)).collect();
            snap.describe(&procs)
        },
        kill: Some(Kill {
            pids,
            track: None,
            label: if count > 1 { "Stop all" } else { "Stop" },
        }),
    }
}

/// What identifies "the same command": the arguments, with the runtime
/// reduced to its name so `bun` and `~/.bun/bin/bun` match.
fn command_key(args: &str) -> String {
    let mut tokens = args.split_whitespace();
    let first = tokens.next().map(base).unwrap_or("");
    std::iter::once(first).chain(tokens).collect::<Vec<_>>().join(" ")
}

/// A short readable name for a command: the package and script it runs out
/// of node_modules ("alchemy dev"), or the command line itself.
pub(crate) fn command_label(args: &str) -> String {
    let tokens: Vec<&str> = args.split_whitespace().collect();
    let label = match tokens.iter().rposition(|t| t.contains("/node_modules/")) {
        Some(i) => {
            let tail = tokens[i].rsplit("/node_modules/").next().unwrap_or("");
            let parts: Vec<&str> = tail.split('/').collect();
            let take = if parts[0].starts_with('@') { 2 } else { 1 };
            let package = parts[..take.min(parts.len())].join("/");
            let script = Path::new(tail)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            // `.bin/rea` is a link to some package's command: the command is the name.
            let package = if package == ".bin" { script.clone() } else { package };
            let mut words = vec![package.clone()];
            let generic = ["index", "cli", "main", "bin"].contains(&script.as_str());
            if script != base(&package) && !generic && tail.contains('/') {
                words.push(script);
            }
            words.extend(tokens[i + 1..].iter().map(|t| t.to_string()));
            words.join(" ")
        }
        None => {
            let mut words = vec![base(tokens.first().copied().unwrap_or(""))];
            words.extend(tokens.iter().skip(1));
            words.join(" ")
        }
    };
    const MAX: usize = 48;
    if label.chars().count() > MAX {
        format!("{}…", label.chars().take(MAX - 1).collect::<String>())
    } else {
        label
    }
}

/// Hides the values of arguments that look like credentials, such as
/// `--api-key abc` or `--token=abc`, so they never end up on screen.
pub(crate) fn redact(args: &str) -> String {
    let secret = |name: &str| {
        let name = name.to_ascii_lowercase();
        ["key", "token", "secret", "password", "passwd", "auth"].iter().any(|w| name.contains(w))
    };
    let mut out = Vec::new();
    let mut hide_next = false;
    for token in args.split_whitespace() {
        if hide_next && !token.starts_with('-') {
            out.push("•••".to_string());
            hide_next = false;
            continue;
        }
        hide_next = false;
        match token.split_once('=') {
            Some((name, _)) if name.starts_with('-') && secret(name) => out.push(format!("{name}=•••")),
            _ => {
                hide_next = token.starts_with('-') && secret(token);
                out.push(token.to_string());
            }
        }
    }
    out.join(" ")
}

fn base(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: &str = "/Users/d";
    const UID: u32 = 501;
    const MB: u64 = 1024 * 1024;

    fn proc(pid: u32, ppid: u32, run_secs: u64, args: &str) -> Proc {
        let path = args.split_whitespace().next().unwrap().to_string();
        Proc {
            pid,
            ppid,
            uid: UID,
            name: base(&path).to_string(),
            path,
            args: args.to_string(),
            cpu_now: 0.0,
            cpu_secs: 0,
            run_secs,
            mem: 100 * MB,
            responsible: None,
        }
    }

    const ALCHEMY: &str = "/Users/d/code/shop/node_modules/.bun/alchemy@2.0.0-beta.84/node_modules/alchemy";
    const H: u64 = 3600;

    /// A machine with dev servers left behind for days, plus things that must not be flagged.
    fn fixture() -> Snapshot {
        let alchemy_dev = format!("/Users/d/.bun/bin/bun {ALCHEMY}/bin/alchemy.js dev");
        let sidecar = format!("bun run {ALCHEMY}/src/Local/Sidecar.ts");
        let exec = format!("bun run {ALCHEMY}/bin/exec.js");
        let vite = "/Users/d/.vite-plus/js_runtime/node/26.13.0/bin/node /Users/d/code/shop/node_modules/.bun/@voidzero-dev+vite-plus-core@1/node_modules/@voidzero-dev/vite-plus-core/dist/cli.js";
        let blog_alchemy = "/Users/d/.bun/bin/bun /Users/d/code/blog/node_modules/.bun/alchemy@2.0.0-beta.83/node_modules/alchemy/bin/alchemy.js dev";
        let workerd = "/Users/d/code/blog/node_modules/.bun/@cloudflare+workerd-darwin-arm64@1/node_modules/@cloudflare/workerd-darwin-arm64/bin/workerd serve";
        let landing = "/Users/d/.vite-plus/js_runtime/node/24.21.0/bin/node /Users/d/Desktop/code.nosync/landing/node_modules/vite/bin/vite.js";

        let procs = vec![
            // shop: five `alchemy dev` left behind, each with helpers.
            proc(8328, 1, 11 * DAY, &alchemy_dev),
            proc(17816, 8328, 6 * DAY, &sidecar),
            proc(42140, 8328, 4 * DAY, &exec),
            proc(32232, 1, 10 * DAY, &alchemy_dev),
            proc(42137, 32232, 4 * DAY, &exec),
            proc(51795, 1, 9 * DAY, &alchemy_dev),
            proc(51979, 1, 9 * DAY, &alchemy_dev),
            proc(70916, 1, 9 * DAY, &alchemy_dev),
            proc(8656, 1, 11 * DAY, vite),
            // platform: `bun --watch` with nothing in its arguments but
            // a relative path, so only its working directory names it.
            proc(28729, 1, 31 * DAY, "bun --watch src/index.ts"),
            proc(11929, 28729, 31 * DAY, "/Users/d/.bun/bin/bun src/index.ts"),
            // blog: two `bun run dev` whose terminals are still open.
            proc(60369, 900, 19 * DAY, "bun run dev"),
            proc(60374, 60369, 19 * DAY, blog_alchemy),
            proc(54574, 60374, 15 * DAY, workerd),
            proc(80581, 901, 18 * DAY, "bun run dev"),
            // landing
            proc(79884, 1, 26 * DAY, landing),
            // A benchmark an earlier agent session left behind in its scratchpad.
            proc(10817, 1, 12 * DAY, "/Users/d/.vite-plus/js_runtime/node/24.22.1/bin/node bench.mjs 3 results.json"),
            // Must not be flagged: a Claude session and the MCP server it runs,
            proc(900, 1, 40 * DAY, "/bin/zsh"),
            proc(14735, 900, 2 * DAY, "/Users/d/.local/share/claude/versions/2.1.0"),
            proc(14800, 14735, 2 * DAY, "node /Users/d/.npm/_npx/abc/node_modules/.bin/mcp-server"),
            // a dev server started an hour ago,
            proc(99000, 900, H, "bun run dev"),
            proc(99001, 99000, H, "/Users/d/.bun/bin/bun /Users/d/code/new/node_modules/vite/bin/vite.js"),
            // a Homebrew service, a script run from ~, and a system process.
            proc(5000, 1, 30 * DAY, "/opt/homebrew/bin/node /opt/homebrew/lib/node_modules/foo/index.js"),
            proc(5001, 1, 30 * DAY, "/usr/local/bin/node server.js"),
            proc(5002, 1, 30 * DAY, "/Applications/Thing.app/Contents/MacOS/node"),
        ];
        let mut root_owned = proc(5003, 1, 30 * DAY, "/Users/d/code/x/node_modules/.bin/node");
        root_owned.uid = 0;
        let mut procs = procs;
        procs.push(root_owned);

        let cwds = [
            (28729, "/Users/d/code/platform/apps/worker"),
            (11929, "/Users/d/code/platform/apps/worker"),
            (60369, "/Users/d/code/blog"),
            (80581, "/Users/d/code/blog"),
            (99000, "/Users/d/code/new"),
            (5001, "/Users/d"),
            (10817, "/private/tmp/claude-501/x/scratchpad/bench"),
        ]
        .into_iter()
        .map(|(pid, dir)| (pid, dir.to_string()))
        .collect();

        Snapshot {
            procs,
            cwds,
            home: HOME.into(),
            uid: UID,
            uptime: 40 * DAY,
            swap_used: 7300 * MB,
            swap_total: 8192 * MB,
            pressure: Some(1),
        }
    }

    fn pids_of(findings: &[Finding], key: &str) -> Vec<u32> {
        let f = findings.iter().find(|f| f.key == key).unwrap_or_else(|| panic!("{key} missing"));
        f.kill.as_ref().unwrap().pids.clone()
    }

    #[test]
    fn flags_every_forgotten_project_and_nothing_else() {
        let found = find(&fixture());
        let mut keys: Vec<&str> = found.iter().map(|f| f.key.as_str()).collect();
        keys.sort();
        let mut expected = [
            "dev:/Users/d/Desktop/code.nosync/landing",
            "dev:/Users/d/code/shop",
            "dev:/Users/d/code/platform/apps/worker",
            "dev:/Users/d/code/blog",
            "dev:/private/tmp/claude-501/x/scratchpad/bench",
        ];
        expected.sort();
        assert_eq!(keys, expected);
    }

    #[test]
    fn stops_whole_trees_parents_first() {
        let found = find(&fixture());
        let shop = pids_of(&found, "dev:/Users/d/code/shop");
        for pid in [8328, 17816, 42140, 32232, 42137, 51795, 51979, 70916, 8656] {
            assert!(shop.contains(&pid), "{pid} not stopped");
        }
        let at = |pid| shop.iter().position(|&p| p == pid).unwrap();
        assert!(at(8328) < at(17816) && at(8328) < at(42140));

        let blog = pids_of(&found, "dev:/Users/d/code/blog");
        assert_eq!(blog, [60369, 60374, 54574, 80581]);
        let worker = pids_of(&found, "dev:/Users/d/code/platform/apps/worker");
        assert_eq!(worker, [28729, 11929]);
    }

    #[test]
    fn leaves_live_sessions_alone() {
        let found = find(&fixture());
        let all: HashSet<u32> = found.iter().flat_map(|f| f.kill.as_ref().unwrap().pids.clone()).collect();
        for pid in [900, 14735, 14800, 99000, 99001, 5000, 5001, 5002, 5003] {
            assert!(!all.contains(&pid), "{pid} should not be stopped");
        }
    }

    #[test]
    fn describes_what_is_running() {
        let found = find(&fixture());
        let shop = found.iter().find(|f| f.key.ends_with("shop")).unwrap();
        assert_eq!(shop.title, "Forgotten dev servers in ~/code/shop");
        assert!(shop.detail.starts_with("5× alchemy dev, @voidzero-dev/vite-plus-core"), "{}", shop.detail);
        assert!(shop.hint.starts_with("The terminal that started them is gone"));

        let blog = found.iter().find(|f| f.key.ends_with("blog")).unwrap();
        assert!(blog.detail.starts_with("2× bun run dev"), "{}", blog.detail);
        assert!(blog.hint.starts_with("The same command is running more than once"));
    }

    #[test]
    fn labels() {
        assert_eq!(command_label("bun --watch src/index.ts"), "bun --watch src/index.ts");
        assert_eq!(command_label(&format!("bun run {ALCHEMY}/bin/exec.js")), "alchemy exec");
        assert_eq!(command_label(&format!("bun {ALCHEMY}/bin/alchemy.js dev")), "alchemy dev");
    }

    #[test]
    fn hides_credentials() {
        assert_eq!(
            redact("node ctx7-mcp --api-key sk-123 --token=abc --port 80"),
            "node ctx7-mcp --api-key ••• --token=••• --port 80"
        );
        assert_eq!(command_label("node /Users/d/.npm/_npx/a/node_modules/.bin/rea mcp"), "rea mcp");
    }

    #[test]
    fn projects() {
        assert_eq!(project_dir("/Users/d", HOME), None);
        assert_eq!(project_dir("/Users/d/.npm/_npx/abc", HOME), None);
        assert_eq!(project_dir("/opt/homebrew/lib", HOME), None);
        assert_eq!(project_dir("/Users/dx/p", HOME), None);
        assert_eq!(project_dir("/Users/d/p/", HOME).as_deref(), Some("/Users/d/p"));
        assert_eq!(project_dir("/private/tmp/x", HOME).as_deref(), Some("/private/tmp/x"));
    }
}
