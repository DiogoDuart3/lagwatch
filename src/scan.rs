//! Takes a snapshot of the machine and turns it into a list of findings.
//!
//! The process table comes from `ps` and `sysctl`: unlike the libproc APIs
//! they report CPU time for processes owned by other users without needing
//! root. libproc is still used for what `ps` cannot tell: memory footprint and
//! working directory, which only matter for the user's own processes anyway.

use std::collections::{HashMap, HashSet};
use std::mem::MaybeUninit;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::dev;

pub(crate) const MIB: u64 = 1024 * 1024;
pub(crate) const GIB: u64 = 1024 * MIB;
pub(crate) const HOUR: u64 = 3600;
pub(crate) const DAY: u64 = 24 * HOUR;

// A process is a CPU hog when it has averaged at least half a core over its
// whole life and has been alive long enough for that not to be a normal burst.
const HOG_MIN_RUNTIME: u64 = 10 * 60;
const HOG_MIN_CORE_FRACTION: f64 = 0.5;

// Something the user already stopped once gets no such patience: if it comes
// back and is busy straight away, stopping it did not fix anything.
const RELAPSE_MIN_RUNTIME: u64 = 10;
const RELAPSE_MIN_CPU: f32 = 50.0;

const SWAP_MIN_FRACTION: f64 = 0.75;
const SWAP_MIN_BYTES: u64 = 2 * GIB;

const GROUP_BIG_BYTES: u64 = 3 * GIB;
const GROUP_STALE_COUNT: usize = 5;
const GROUP_STALE_AGE: u64 = 2 * DAY;
const GROUP_STALE_BYTES: u64 = GIB;

const LONG_UPTIME: u64 = 7 * DAY;

// Anything launchd starts from these places is a daemon or an app, not an orphan.
pub(crate) const MANAGED_PREFIXES: [&str; 5] = [
    "/System/",
    "/usr/libexec/",
    "/usr/sbin/",
    "/Library/",
    "/Applications/",
];

#[derive(Clone, Copy, PartialEq)]
pub enum Severity {
    Warn,
    Info,
}

#[derive(Clone)]
pub struct Finding {
    pub severity: Severity,
    /// Stable identity across scans.
    pub key: String,
    pub title: String,
    pub detail: String,
    pub hint: String,
    /// Set when stopping a process is the way to resolve this.
    pub kill: Option<Kill>,
    /// One line per process involved, biggest first, for a closer look.
    pub processes: Vec<String>,
}

#[derive(Clone)]
pub struct Kill {
    /// Stopped in this order; parents come before their children.
    pub pids: Vec<u32>,
    /// A process name to watch for coming back after it was stopped.
    pub track: Option<String>,
    pub label: &'static str,
}

pub(crate) struct Proc {
    pub(crate) pid: u32,
    pub(crate) ppid: u32,
    pub(crate) uid: u32,
    pub(crate) name: String,
    pub(crate) path: String,
    pub(crate) args: String,
    pub(crate) cpu_now: f32,
    pub(crate) cpu_secs: u64,
    pub(crate) run_secs: u64,
    /// Memory footprint, swapped and compressed pages included, as Activity
    /// Monitor shows it. Resident size for other users' processes, which
    /// misses whatever has been swapped out.
    pub(crate) mem: u64,
    /// The app macOS holds responsible for it: Safari for its web content
    /// processes, the terminal for a command started there.
    pub(crate) responsible: Option<u32>,
}

pub struct Snapshot {
    pub(crate) procs: Vec<Proc>,
    /// Working directories of the user's runtimes whose arguments do not say
    /// which project they belong to.
    pub(crate) cwds: HashMap<u32, String>,
    pub(crate) home: String,
    pub(crate) uid: u32,
    pub uptime: u64,
    pub swap_used: u64,
    pub swap_total: u64,
    pub pressure: Option<u32>,
}

impl Snapshot {
    pub fn take() -> Self {
        let (swap_total, swap_used) = swap_usage().unwrap_or((0, 0));
        let procs = processes();
        let home = std::env::var("HOME").unwrap_or_default();
        let uid = unsafe { libc::getuid() };
        let cwds = procs
            .iter()
            .filter(|p| dev::is_runtime(p, uid) && dev::modules_project(&p.args, &home).is_none())
            .filter_map(|p| Some((p.pid, cwd(p.pid)?)))
            .collect();
        Snapshot {
            procs,
            cwds,
            home,
            uid,
            uptime: uptime().unwrap_or(0),
            swap_used,
            swap_total,
            pressure: sysctl("kern.memorystatus_vm_pressure_level")
                .and_then(|s| s.trim().parse().ok()),
        }
    }

    pub fn process_count(&self) -> usize {
        self.procs.len()
    }

    pub fn pressure_name(&self) -> &'static str {
        match self.pressure {
            Some(1) => "normal",
            Some(2) => "elevated",
            Some(4) => "critical",
            _ => "unknown",
        }
    }

    /// `stopped` holds the names of processes the user already stopped.
    pub fn findings(&self, stopped: &HashSet<String>) -> Vec<Finding> {
        let mut findings = Vec::new();
        let dev = dev::find(self);
        self.cpu_hogs(stopped, &mut findings);
        self.memory(!dev.is_empty(), &mut findings);
        findings.extend(dev);
        self.groups(&mut findings);
        findings.sort_by_key(|f| f.severity == Severity::Info);
        findings
    }

    fn cpu_hogs(&self, stopped: &HashSet<String>, out: &mut Vec<Finding>) {
        let mut hogs: Vec<(&Proc, f64, bool)> = self
            .procs
            .iter()
            .filter_map(|p| {
                let frac = p.cpu_secs as f64 / p.run_secs.max(1) as f64;
                let lifetime = p.run_secs >= HOG_MIN_RUNTIME && frac >= HOG_MIN_CORE_FRACTION;
                let relapsed = stopped.contains(&p.name)
                    && p.run_secs >= RELAPSE_MIN_RUNTIME
                    && p.cpu_now >= RELAPSE_MIN_CPU;
                (lifetime || relapsed).then_some((p, frac, !lifetime))
            })
            .collect();
        hogs.sort_by(|a, b| b.0.cpu_secs.cmp(&a.0.cpu_secs));

        for (p, frac, relapsed) in hogs {
            let managed = MANAGED_PREFIXES.iter().any(|prefix| p.path.starts_with(prefix));
            let daemon = p.ppid == 1 && managed;
            let (kind, hint) = if relapsed {
                (
                    "Still busy after being stopped",
                    "Stopping it did not help: the new instance is just as busy.",
                )
            } else if daemon {
                (
                    "CPU hog",
                    "System-managed, so macOS starts it again after a restart.",
                )
            } else if p.ppid == 1 {
                (
                    "Orphaned runaway",
                    "Its parent is gone, so nothing is waiting for it.",
                )
            } else {
                ("CPU hog", "Check whether it is still doing useful work.")
            };
            out.push(Finding {
                severity: Severity::Warn,
                // Daemons come back under a new pid, so they are tracked by name.
                key: if daemon {
                    format!("hog:{}", p.name)
                } else {
                    format!("hog:{}", p.pid)
                },
                title: format!("{kind}: {} (pid {})", p.name, p.pid),
                detail: format!(
                    "{} of CPU time in {} alive ({:.0}% of a core on average, {:.0}% right now)",
                    dur(p.cpu_secs),
                    dur(p.run_secs),
                    frac * 100.0,
                    p.cpu_now
                ),
                hint: hint.into(),
                kill: Some(Kill {
                    pids: vec![p.pid],
                    track: Some(p.name.clone()),
                    label: if daemon { "Restart" } else { "Kill" },
                }),
                processes: Vec::new(),
            });
        }
    }

    fn memory(&self, dev_servers: bool, out: &mut Vec<Finding>) {
        let first = if dev_servers {
            "Stop the forgotten dev servers below first."
        } else {
            "Close apps and sessions you are not using."
        };
        let uptime_note = if self.uptime >= LONG_UPTIME {
            format!(" Uptime is {}, so a reboot is the quick fix.", dur(self.uptime))
        } else {
            String::new()
        };

        if let Some(level) = self.pressure.filter(|l| *l >= 2) {
            let name = if level >= 4 { "critical" } else { "elevated" };
            out.push(Finding {
                severity: Severity::Warn,
                key: "pressure".into(),
                title: format!("Memory pressure is {name}"),
                detail: "macOS is actively struggling to find free memory".into(),
                hint: format!("Quit the biggest apps listed below.{uptime_note}"),
                kill: None,
                processes: Vec::new(),
            });
        }

        let fraction = if self.swap_total > 0 {
            self.swap_used as f64 / self.swap_total as f64
        } else {
            0.0
        };
        if fraction >= SWAP_MIN_FRACTION && self.swap_used >= SWAP_MIN_BYTES {
            out.push(Finding {
                severity: Severity::Warn,
                key: "swap".into(),
                title: format!("Swap is {:.0}% full", fraction * 100.0),
                detail: format!(
                    "{} of {} in use; switching apps has to read memory back from disk",
                    size(self.swap_used),
                    size(self.swap_total)
                ),
                hint: format!("{first}{uptime_note}"),
                kill: None,
                processes: Vec::new(),
            });
        }
    }

    fn groups(&self, out: &mut Vec<Finding>) {
        let mut by_name: HashMap<&str, Vec<&Proc>> = HashMap::new();
        for p in &self.procs {
            by_name.entry(p.name.as_str()).or_default().push(p);
        }

        let mut flagged: Vec<(&str, Vec<&Proc>, u64, usize)> = by_name
            .into_iter()
            .filter_map(|(name, procs)| {
                let total: u64 = procs.iter().map(|p| p.mem).sum();
                let stale = procs.iter().filter(|p| p.run_secs >= GROUP_STALE_AGE).count();
                let big = total >= GROUP_BIG_BYTES;
                let piled_up = stale >= GROUP_STALE_COUNT && total >= GROUP_STALE_BYTES;
                (big || piled_up).then_some((name, procs, total, stale))
            })
            .collect();
        flagged.sort_by_key(|f| std::cmp::Reverse(f.2));

        for (name, procs, total, stale) in flagged {
            let count = procs.len();
            let age = if stale > 0 {
                format!(", {stale} older than {}", dur(GROUP_STALE_AGE))
            } else {
                String::new()
            };
            // "Which app is this?" is the first question about a pile of
            // helpers, and the answer is usually lopsided.
            let mut apps: Vec<(String, usize, u64)> = Vec::new();
            for p in &procs {
                let Some(app) = self.app_of(p) else { continue };
                match apps.iter_mut().find(|(a, _, _)| *a == app) {
                    Some((_, n, mem)) => {
                        *n += 1;
                        *mem += p.mem;
                    }
                    None => apps.push((app, 1, p.mem)),
                }
            }
            apps.sort_by_key(|a| std::cmp::Reverse(a.2));
            let by_app = if apps.is_empty() {
                String::new()
            } else {
                let mut parts: Vec<String> = apps
                    .iter()
                    .take(4)
                    .map(|(app, n, mem)| format!("{app} {n} ({})", size(*mem)))
                    .collect();
                if apps.len() > 4 {
                    parts.push(format!("{} more apps", apps.len() - 4));
                }
                format!(" · from {}", parts.join(", "))
            };
            out.push(Finding {
                severity: Severity::Info,
                key: format!("group:{name}"),
                title: format!("{name}: {count} processes using {}", size(total)),
                detail: format!("{count} running{age}{by_app}"),
                hint: "Close the ones you are not using.".into(),
                kill: None,
                processes: self.describe(&procs),
            });
        }
    }

    /// The app responsible for a process, when that is some other process.
    pub(crate) fn app_of(&self, p: &Proc) -> Option<String> {
        let owner = self.procs.iter().find(|o| Some(o.pid) == p.responsible)?;
        // Command-line tools rename themselves ("npm exec foo"): the tool is enough.
        let tool = || owner.name.split_whitespace().next().unwrap_or(&owner.name).to_string();
        Some(app_name(&owner.path).unwrap_or_else(tool))
    }

    /// One line per process, biggest first: size, age, pid, what it runs and
    /// for which app.
    pub(crate) fn describe(&self, procs: &[&Proc]) -> Vec<String> {
        let mut procs = procs.to_vec();
        procs.sort_by_key(|p| std::cmp::Reverse(p.mem));
        procs
            .iter()
            .map(|p| {
                let command = dev::command_label(&dev::redact(&p.args));
                let app = self.app_of(p);
                let what = match app {
                    // A helper with no arguments says nothing beyond its app.
                    Some(app) if command == p.name || p.args == p.path => app,
                    Some(app) => format!("{command} · {app}"),
                    None => command,
                };
                format!("{:>8}  {:>7}  pid {:<6} {what}", size(p.mem), dur(p.run_secs), p.pid)
            })
            .collect()
    }
}

fn run(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn sysctl(name: &str) -> Option<String> {
    run("/usr/sbin/sysctl", &["-n", name])
}

/// Parses `total = 12288.00M  used = 10570.81M  free = ...` into bytes.
fn swap_usage() -> Option<(u64, u64)> {
    let text = sysctl("vm.swapusage")?;
    let field = |name: &str| {
        let rest = text.split(&format!("{name} = ")).nth(1)?;
        let megabytes: f64 = rest.split('M').next()?.trim().parse().ok()?;
        Some((megabytes * MIB as f64) as u64)
    };
    Some((field("total")?, field("used")?))
}

/// Parses `{ sec = 1790719576, usec = 87860 } ...` into seconds since boot.
fn uptime() -> Option<u64> {
    let text = sysctl("kern.boottime")?;
    let boot: u64 = text.split("sec = ").nth(1)?.split(',').next()?.parse().ok()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(now.saturating_sub(boot))
}

fn processes() -> Vec<Proc> {
    let me = std::process::id();
    let table = run("/bin/ps", &["-axo", "pid=,ppid=,uid=,etime=,time=,pcpu=,rss=,comm="]);
    let args = run("/bin/ps", &["-axo", "pid=,args="]).unwrap_or_default();
    let args: HashMap<u32, &str> = args
        .lines()
        .filter_map(|line| {
            let mut rest = line;
            Some((take(&mut rest)?.parse().ok()?, rest.trim()))
        })
        .collect();

    table
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let mut rest = line;
            let pid: u32 = take(&mut rest)?.parse().ok()?;
            let ppid = take(&mut rest)?.parse().ok()?;
            let uid = take(&mut rest)?.parse().ok()?;
            let run_secs = clock(take(&mut rest)?)?;
            let cpu_secs = clock(take(&mut rest)?)?;
            let cpu_now = take(&mut rest)?.parse().ok()?;
            let rss_kib: u64 = take(&mut rest)?.parse().ok()?;
            let path = rest.trim().to_string();
            let args = args.get(&pid).copied().unwrap_or("");
            (pid != me && pid != 0).then(|| Proc {
                pid,
                ppid,
                uid,
                name: display_name(&path, args),
                path,
                args: args.to_string(),
                cpu_now,
                cpu_secs,
                run_secs,
                mem: footprint(pid).unwrap_or(rss_kib * 1024),
                responsible: responsible(pid),
            })
        })
        .collect()
}

unsafe extern "C" {
    // Private but stable: what Activity Monitor uses to tie helpers to apps.
    fn responsibility_get_pid_responsible_for_pid(pid: libc::pid_t) -> libc::pid_t;
}

fn responsible(pid: u32) -> Option<u32> {
    let owner = unsafe { responsibility_get_pid_responsible_for_pid(pid as i32) };
    (owner > 0 && owner as u32 != pid).then_some(owner as u32)
}

/// "Safari" for anything inside Safari.app: the outermost bundle wins, so
/// helpers nested inside an app are named after the app.
fn app_name(path: &str) -> Option<String> {
    let end = path.find(".app/").or_else(|| path.strip_suffix(".app").map(str::len))?;
    let start = path[..end].rfind('/').map_or(0, |i| i + 1);
    Some(path[start..end].to_string())
}

/// What the process really occupies, including pages macOS has compressed or
/// swapped out. Only readable for the user's own processes.
fn footprint(pid: u32) -> Option<u64> {
    let mut info = MaybeUninit::<libc::rusage_info_v2>::zeroed();
    let rc = unsafe {
        libc::proc_pid_rusage(pid as i32, libc::RUSAGE_INFO_V2, info.as_mut_ptr().cast())
    };
    (rc == 0).then(|| unsafe { info.assume_init() }.ri_phys_footprint)
}

fn cwd(pid: u32) -> Option<String> {
    let mut info = MaybeUninit::<libc::proc_vnodepathinfo>::zeroed();
    let len = std::mem::size_of::<libc::proc_vnodepathinfo>() as i32;
    let got = unsafe {
        libc::proc_pidinfo(pid as i32, libc::PROC_PIDVNODEPATHINFO, 0, info.as_mut_ptr().cast(), len)
    };
    if got != len {
        return None;
    }
    let info = unsafe { info.assume_init() };
    let bytes: Vec<u8> = info
        .pvi_cdir
        .vip_path
        .as_flattened()
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    (!bytes.is_empty()).then(|| String::from_utf8_lossy(&bytes).into_owned())
}

/// Pops the next whitespace-separated column off the front of `rest`.
fn take<'a>(rest: &mut &'a str) -> Option<&'a str> {
    let s = rest.trim_start();
    let end = s.find(char::is_whitespace).unwrap_or(s.len());
    let (token, tail) = s.split_at(end);
    *rest = tail;
    (!token.is_empty()).then_some(token)
}

/// Parses ps durations: `[[dd-]hh:]mm:ss[.cc]`, where minutes may exceed 59.
fn clock(text: &str) -> Option<u64> {
    let (days, rest) = match text.split_once('-') {
        Some((d, rest)) => (d.parse::<u64>().ok()?, rest),
        None => (0, text),
    };
    let mut secs = 0.0;
    for part in rest.split(':') {
        secs = secs * 60.0 + part.parse::<f64>().ok()?;
    }
    Some(days * DAY + secs as u64)
}

/// Versioned binaries have paths ending in things like "2.1.287", so when the
/// process was invoked under another name ("claude") show that instead.
fn display_name(path: &str, args: &str) -> String {
    let invoked = if args.starts_with(path) {
        path
    } else {
        args.split_whitespace().next().unwrap_or(path)
    };
    let base = |p: &str| Path::new(p).file_name().map(|n| n.to_string_lossy().into_owned());
    base(invoked).or_else(|| base(path)).unwrap_or_else(|| path.to_string())
}

pub fn dur(secs: u64) -> String {
    let (d, h, m) = (secs / DAY, secs % DAY / HOUR, secs % HOUR / 60);
    if d > 0 {
        format!("{d}d {h}h")
    } else if h > 0 {
        format!("{h}h {m}m")
    } else {
        format!("{m}m")
    }
}

pub fn size(bytes: u64) -> String {
    if bytes >= GIB {
        format!("{:.1} GB", bytes as f64 / GIB as f64)
    } else {
        format!("{} MB", bytes / MIB)
    }
}
