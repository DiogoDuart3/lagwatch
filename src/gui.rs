//! The window: a live list of findings that rescans every few seconds and can
//! close itself once every problem it showed has gone away.
//!
//! Built directly on AppKit so it looks and behaves like any other Mac app.

use std::cell::{OnceCell, RefCell};
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject, Sel};
use objc2::{define_class, msg_send, sel, DefinedClass, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSApplication, NSApplicationActivationPolicy, NSApplicationDelegate, NSBackingStoreType,
    NSBox, NSBoxType, NSButton, NSColor, NSControlStateValueOff, NSControlStateValueOn, NSFont,
    NSImage, NSImageView, NSLayoutAttribute, NSLayoutConstraintOrientation, NSMenu, NSMenuItem,
    NSScrollView, NSStackView, NSTextField, NSTitlePosition, NSUserInterfaceLayoutOrientation,
    NSView, NSWindow, NSWindowStyleMask,
};
use objc2_foundation::{
    ns_string, NSNotification, NSObject, NSObjectProtocol, NSPoint, NSRect, NSSize, NSString,
    NSTimer,
};

use crate::scan::{self, Finding, Severity, Snapshot};

const SCAN_EVERY: Duration = Duration::from_secs(5);
const CLOSE_DELAY: Duration = Duration::from_secs(3);
// After stopping something, wait this long before believing it stayed fixed:
// system daemons are started again by macOS and may be just as busy.
const VERIFY_FOR: Duration = Duration::from_secs(30);
// How long a process gets to exit on its own before it is forced to.
const STOP_GRACE: Duration = Duration::from_secs(3);

const SHOWN_PROCESSES: usize = 25;

const MARGIN: f64 = 16.0;
const CARD_PADDING: f64 = 12.0;

struct Scan {
    snapshot: Snapshot,
    findings: Vec<Finding>,
}

#[derive(Default)]
struct Shared {
    latest: Mutex<Option<Scan>>,
    /// Bumped on every finished scan, so the window knows when to redraw.
    generation: AtomicU64,
    /// Names of processes stopped from this window.
    stopped: Mutex<HashSet<String>>,
    /// Outcome of the last stop, waiting to be shown: `Some(None)` is success.
    stop_result: Mutex<Option<Option<String>>>,
    rescan: AtomicBool,
}

struct State {
    auto_close: bool,
    /// Warnings the user chose to stop caring about for this run.
    ignored: HashSet<String>,
    /// Findings whose process list is open.
    expanded: HashSet<String>,
    /// Auto-close only makes sense once there has been something to fix.
    had_problems: bool,
    all_clear_since: Option<Instant>,
    verify_until: Option<Instant>,
    error: Option<String>,
    /// The findings currently on screen; buttons refer to them by index.
    shown: Vec<Finding>,
    drawn_generation: u64,
}

struct Ui {
    summary: Retained<NSTextField>,
    status: Retained<NSTextField>,
    cards: Retained<NSStackView>,
    // Kept alive for as long as the app runs.
    _window: Retained<NSWindow>,
}

struct Ivars {
    shared: Arc<Shared>,
    state: RefCell<State>,
    ui: OnceCell<Ui>,
}

define_class!(
    // A document view that lays out from the top, so short lists do not sink
    // to the bottom of the scroll view.
    #[unsafe(super(NSView))]
    #[thread_kind = MainThreadOnly]
    #[name = "LagwatchFlippedView"]
    struct FlippedView;

    impl FlippedView {
        #[unsafe(method(isFlipped))]
        fn is_flipped(&self) -> bool {
            true
        }
    }
);

define_class!(
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "LagwatchController"]
    #[ivars = Ivars]
    struct Controller;

    unsafe impl NSObjectProtocol for Controller {}

    unsafe impl NSApplicationDelegate for Controller {
        #[unsafe(method(applicationDidFinishLaunching:))]
        fn did_finish_launching(&self, _notification: &NSNotification) {
            self.build_window();
            spawn_scanner(self.ivars().shared.clone());
            unsafe {
                NSTimer::scheduledTimerWithTimeInterval_target_selector_userInfo_repeats(
                    0.25,
                    self,
                    sel!(tick:),
                    None,
                    true,
                );
            }
        }

        #[unsafe(method(applicationShouldTerminateAfterLastWindowClosed:))]
        fn terminate_after_last_window(&self, _app: &NSApplication) -> bool {
            true
        }
    }

    impl Controller {
        #[unsafe(method(tick:))]
        fn tick(&self, _timer: &NSTimer) {
            if let Some(result) = self.ivars().shared.stop_result.lock().unwrap().take() {
                self.ivars().state.borrow_mut().error = result;
            }
            let generation = self.ivars().shared.generation.load(Ordering::Relaxed);
            if generation != self.ivars().state.borrow().drawn_generation {
                self.redraw();
            }
            self.update_status();
        }

        #[unsafe(method(toggleAutoClose:))]
        fn toggle_auto_close(&self, sender: &NSButton) {
            let on = sender.state() == NSControlStateValueOn;
            self.ivars().state.borrow_mut().auto_close = on;
            save_auto_close(on);
        }

        #[unsafe(method(stopProcess:))]
        fn stop_process(&self, sender: &NSButton) {
            let ivars = self.ivars();
            let Some(target) = self.finding_for(sender).and_then(|f| f.kill) else {
                return;
            };
            if let Some(name) = target.track {
                ivars.shared.stopped.lock().unwrap().insert(name);
            }
            let mut state = ivars.state.borrow_mut();
            state.verify_until = Some(Instant::now() + VERIFY_FOR + STOP_GRACE);
            state.error = None;
            // Stopping can take a few seconds, which the window must not wait out.
            let shared = ivars.shared.clone();
            thread::spawn(move || {
                let result = stop(&target.pids);
                *shared.stop_result.lock().unwrap() = Some(result.err());
                shared.rescan.store(true, Ordering::Relaxed);
            });
        }

        #[unsafe(method(toggleProcesses:))]
        fn toggle_processes(&self, sender: &NSButton) {
            if let Some(finding) = self.finding_for(sender) {
                let mut state = self.ivars().state.borrow_mut();
                if !state.expanded.remove(&finding.key) {
                    state.expanded.insert(finding.key);
                }
                drop(state);
                self.redraw();
            }
        }

        #[unsafe(method(ignoreFinding:))]
        fn ignore_finding(&self, sender: &NSButton) {
            if let Some(finding) = self.finding_for(sender) {
                self.ivars().state.borrow_mut().ignored.insert(finding.key);
                self.redraw();
            }
        }
    }
);

pub fn run() {
    let mtm = MainThreadMarker::new().expect("the window must be started on the main thread");
    let app = NSApplication::sharedApplication(mtm);
    app.setActivationPolicy(NSApplicationActivationPolicy::Regular);

    let controller = Controller::new(mtm);
    app.setDelegate(Some(ProtocolObject::from_ref(&*controller)));
    app.setMainMenu(Some(&main_menu(mtm)));
    app.run();
}

fn spawn_scanner(shared: Arc<Shared>) {
    thread::spawn(move || loop {
        let snapshot = Snapshot::take();
        let findings = snapshot.findings(&shared.stopped.lock().unwrap());
        *shared.latest.lock().unwrap() = Some(Scan { snapshot, findings });
        shared.generation.fetch_add(1, Ordering::Relaxed);

        let started = Instant::now();
        while started.elapsed() < SCAN_EVERY && !shared.rescan.swap(false, Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(200));
        }
    });
}

impl Controller {
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let this = mtm.alloc::<Self>().set_ivars(Ivars {
            shared: Arc::new(Shared::default()),
            state: RefCell::new(State {
                auto_close: load_auto_close(),
                ignored: HashSet::new(),
                expanded: HashSet::new(),
                had_problems: false,
                all_clear_since: None,
                verify_until: None,
                error: None,
                shown: Vec::new(),
                drawn_generation: 0,
            }),
            ui: OnceCell::new(),
        });
        unsafe { msg_send![super(this), init] }
    }

    fn target(&self) -> Option<&AnyObject> {
        Some(self)
    }

    fn finding_for(&self, sender: &NSButton) -> Option<Finding> {
        let state = self.ivars().state.borrow();
        state.shown.get(usize::try_from(sender.tag()).ok()?).cloned()
    }

    fn build_window(&self) {
        let mtm = self.mtm();
        let style = NSWindowStyleMask::Titled
            | NSWindowStyleMask::Closable
            | NSWindowStyleMask::Miniaturizable
            | NSWindowStyleMask::Resizable;
        let frame = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(620.0, 520.0));
        let window = unsafe {
            NSWindow::initWithContentRect_styleMask_backing_defer(
                mtm.alloc(),
                frame,
                style,
                NSBackingStoreType::Buffered,
                false,
            )
        };
        unsafe { window.setReleasedWhenClosed(false) };
        window.setTitle(ns_string!("Lagwatch"));
        window.setContentMinSize(NSSize::new(460.0, 320.0));

        let summary = label("Scanning…", mtm);
        summary.setTextColor(Some(&NSColor::secondaryLabelColor()));

        let checkbox = unsafe {
            NSButton::checkboxWithTitle_target_action(
                ns_string!("Close automatically once the flagged processes are fixed"),
                self.target(),
                Some(sel!(toggleAutoClose:)),
                mtm,
            )
        };
        checkbox.setState(if self.ivars().state.borrow().auto_close {
            NSControlStateValueOn
        } else {
            NSControlStateValueOff
        });

        let status = label("", mtm);
        status.setFont(Some(&NSFont::boldSystemFontOfSize(NSFont::systemFontSize())));
        status.setHidden(true);

        let cards = stack(NSUserInterfaceLayoutOrientation::Vertical, 10.0, mtm);
        let document: Retained<FlippedView> = unsafe { msg_send![mtm.alloc::<FlippedView>(), init] };
        document.setTranslatesAutoresizingMaskIntoConstraints(false);
        document.addSubview(&cards);
        pin(&cards, &document, 0.0);

        let scroll = NSScrollView::new(mtm);
        scroll.setDrawsBackground(false);
        scroll.setHasVerticalScroller(true);
        scroll.setAutohidesScrollers(true);
        scroll.setDocumentView(Some(&document));
        let clip = scroll.contentView();
        for constraint in [
            document.topAnchor().constraintEqualToAnchor(&clip.topAnchor()),
            document.leadingAnchor().constraintEqualToAnchor(&clip.leadingAnchor()),
            document.widthAnchor().constraintEqualToAnchor(&clip.widthAnchor()),
        ] {
            constraint.setActive(true);
        }

        let root = stack(NSUserInterfaceLayoutOrientation::Vertical, 8.0, mtm);
        root.addArrangedSubview(&summary);
        root.addArrangedSubview(&checkbox);
        root.addArrangedSubview(&status);
        root.addArrangedSubview(&scroll);
        root.setCustomSpacing_afterView(12.0, &checkbox);
        let full_width: [&NSView; 3] = [&summary, &status, &scroll];
        for view in full_width {
            view.widthAnchor().constraintEqualToAnchor(&root.widthAnchor()).setActive(true);
        }

        let content = window.contentView().expect("a new window has a content view");
        content.addSubview(&root);
        pin(&root, &content, MARGIN);

        window.center();
        window.makeKeyAndOrderFront(None);
        NSApplication::sharedApplication(mtm).activate();

        let ui = Ui { summary, status, cards, _window: window };
        if self.ivars().ui.set(ui).is_err() {
            unreachable!("the window is only built once");
        }
    }

    /// Rebuilds the summary line and the cards from the latest scan.
    fn redraw(&self) {
        let ivars = self.ivars();
        let Some(ui) = ivars.ui.get() else { return };
        let latest = ivars.shared.latest.lock().unwrap();
        let Some(scan) = latest.as_ref() else { return };
        let mut state = ivars.state.borrow_mut();
        state.drawn_generation = ivars.shared.generation.load(Ordering::Relaxed);

        let snap = &scan.snapshot;
        ui.summary.setStringValue(&NSString::from_str(&format!(
            "Uptime {}   ·   Swap {} / {}   ·   Memory pressure {}   ·   {} processes",
            scan::dur(snap.uptime),
            scan::size(snap.swap_used),
            scan::size(snap.swap_total),
            snap.pressure_name(),
            snap.process_count()
        )));

        let shown: Vec<Finding> = scan
            .findings
            .iter()
            .filter(|f| !state.ignored.contains(&f.key))
            .cloned()
            .collect();

        for view in ui.cards.arrangedSubviews() {
            view.removeFromSuperview();
        }
        for (index, finding) in shown.iter().enumerate() {
            let card = self.card(finding, index, state.expanded.contains(&finding.key));
            ui.cards.addArrangedSubview(&card);
            card.widthAnchor().constraintEqualToAnchor(&ui.cards.widthAnchor()).setActive(true);
        }
        state.shown = shown;
    }

    fn card(&self, finding: &Finding, index: usize, expanded: bool) -> Retained<NSBox> {
        let mtm = self.mtm();
        let warn = finding.severity == Severity::Warn;

        let (symbol, tint) = if warn {
            ("exclamationmark.triangle.fill", NSColor::systemRedColor())
        } else {
            ("info.circle.fill", NSColor::systemOrangeColor())
        };
        let title_row = stack(NSUserInterfaceLayoutOrientation::Horizontal, 6.0, mtm);
        if let Some(image) = NSImage::imageWithSystemSymbolName_accessibilityDescription(
            &NSString::from_str(symbol),
            None,
        ) {
            let icon = NSImageView::imageViewWithImage(&image, mtm);
            icon.setContentTintColor(Some(&tint));
            title_row.addArrangedSubview(&icon);
        }
        let title = label(&finding.title, mtm);
        title.setFont(Some(&NSFont::boldSystemFontOfSize(NSFont::systemFontSize())));
        title_row.addArrangedSubview(&title);

        let hint = label(&finding.hint, mtm);
        hint.setTextColor(Some(&NSColor::secondaryLabelColor()));

        let body = stack(NSUserInterfaceLayoutOrientation::Vertical, 4.0, mtm);
        body.addArrangedSubview(&title_row);
        body.addArrangedSubview(&label(&finding.detail, mtm));
        body.addArrangedSubview(&hint);

        if expanded && !finding.processes.is_empty() {
            let mut lines: Vec<String> = finding
                .processes
                .iter()
                .take(SHOWN_PROCESSES)
                .map(|line| truncate(line, 110))
                .collect();
            if finding.processes.len() > SHOWN_PROCESSES {
                lines.push(format!("… and {} more", finding.processes.len() - SHOWN_PROCESSES));
            }
            let list = label(&lines.join("\n"), mtm);
            list.setSelectable(true);
            list.setFont(Some(&NSFont::monospacedSystemFontOfSize_weight(11.0, 0.0)));
            list.setTextColor(Some(&NSColor::secondaryLabelColor()));
            body.setCustomSpacing_afterView(8.0, &hint);
            body.addArrangedSubview(&list);
        }

        let buttons = stack(NSUserInterfaceLayoutOrientation::Horizontal, 8.0, mtm);
        if warn {
            if let Some(target) = &finding.kill {
                let stop = self.button(target.label, sel!(stopProcess:), index);
                stop.setHasDestructiveAction(true);
                buttons.addArrangedSubview(&stop);
            }
            buttons.addArrangedSubview(&self.button("Ignore", sel!(ignoreFinding:), index));
        }
        if !finding.processes.is_empty() {
            let count = finding.processes.len();
            let title = match (expanded, count) {
                (true, _) => "Hide processes".to_string(),
                (false, 1) => "Show process".to_string(),
                (false, n) => format!("Show {n} processes"),
            };
            buttons.addArrangedSubview(&self.button(&title, sel!(toggleProcesses:), index));
        }
        if !buttons.arrangedSubviews().is_empty() {
            body.setCustomSpacing_afterView(8.0, body.arrangedSubviews().lastObject().as_deref().unwrap());
            body.addArrangedSubview(&buttons);
        }

        let card = NSBox::new(mtm);
        card.setBoxType(NSBoxType::Custom);
        card.setTitlePosition(NSTitlePosition::NoTitle);
        card.setCornerRadius(8.0);
        card.setBorderWidth(1.0);
        card.setBorderColor(&NSColor::separatorColor());
        card.setFillColor(&NSColor::controlBackgroundColor());
        card.setContentViewMargins(NSSize::new(0.0, 0.0));
        card.addSubview(&body);
        pin(&body, &card, CARD_PADDING);
        card
    }

    fn button(&self, title: &str, action: Sel, index: usize) -> Retained<NSButton> {
        let button = unsafe {
            NSButton::buttonWithTitle_target_action(
                &NSString::from_str(title),
                self.target(),
                Some(action),
                self.mtm(),
            )
        };
        button.setTag(index as isize);
        button
    }

    /// Shows the one-line status above the list and quits when everything
    /// that could be fixed has stayed fixed.
    fn update_status(&self) {
        let ivars = self.ivars();
        let Some(ui) = ivars.ui.get() else { return };
        let mut state = ivars.state.borrow_mut();
        if state.drawn_generation == 0 {
            return;
        }

        // Only things that can be fixed from here hold the window open: swap,
        // for one, usually stays full until a reboot.
        let fixable = state.shown.iter().filter(|f| f.kill.is_some()).count();
        let warnings = state.shown.iter().filter(|f| f.severity == Severity::Warn).count();

        let mut closing = None;
        if fixable > 0 {
            state.had_problems = true;
            state.all_clear_since = None;
        } else if state.had_problems && state.auto_close {
            let verifying = state
                .verify_until
                .map(|until| until.saturating_duration_since(Instant::now()))
                .filter(|left| !left.is_zero());
            if let Some(left) = verifying {
                state.all_clear_since = None;
                closing = Some(format!("Checking that it stays fixed… {}s", left.as_secs() + 1));
            } else {
                let since = *state.all_clear_since.get_or_insert_with(Instant::now);
                let left = CLOSE_DELAY.saturating_sub(since.elapsed());
                if left.is_zero() {
                    drop(state);
                    NSApplication::sharedApplication(self.mtm()).terminate(None);
                    return;
                }
                closing = Some(format!("All fixed — closing in {}s", left.as_secs() + 1));
            }
        } else {
            state.all_clear_since = None;
        }

        let (text, color) = if let Some(error) = &state.error {
            (Some(error.clone()), NSColor::systemRedColor())
        } else if closing.is_some() {
            (closing, NSColor::systemGreenColor())
        } else if warnings == 0 {
            (Some("No problems found.".to_string()), NSColor::systemGreenColor())
        } else {
            (None, NSColor::labelColor())
        };
        ui.status.setHidden(text.is_none());
        if let Some(text) = text {
            ui.status.setStringValue(&NSString::from_str(&text));
            ui.status.setTextColor(Some(&color));
        }
    }
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() > max {
        format!("{}…", text.chars().take(max - 1).collect::<String>())
    } else {
        text.to_string()
    }
}

/// A wrapping label that never forces the window wider than it is.
fn label(text: &str, mtm: MainThreadMarker) -> Retained<NSTextField> {
    let label = NSTextField::wrappingLabelWithString(&NSString::from_str(text), mtm);
    label.setSelectable(false);
    label.setContentCompressionResistancePriority_forOrientation(
        250.0,
        NSLayoutConstraintOrientation::Horizontal,
    );
    label
}

fn stack(
    orientation: NSUserInterfaceLayoutOrientation,
    spacing: f64,
    mtm: MainThreadMarker,
) -> Retained<NSStackView> {
    let stack = NSStackView::new(mtm);
    stack.setOrientation(orientation);
    stack.setSpacing(spacing);
    if orientation == NSUserInterfaceLayoutOrientation::Vertical {
        stack.setAlignment(NSLayoutAttribute::Leading);
    }
    stack
}

/// Pins `view` to all four edges of `container`, inset by `margin`.
fn pin(view: &NSView, container: &NSView, margin: f64) {
    view.setTranslatesAutoresizingMaskIntoConstraints(false);
    for constraint in [
        view.topAnchor().constraintEqualToAnchor_constant(&container.topAnchor(), margin),
        view.leadingAnchor().constraintEqualToAnchor_constant(&container.leadingAnchor(), margin),
        container.trailingAnchor().constraintEqualToAnchor_constant(&view.trailingAnchor(), margin),
        container.bottomAnchor().constraintEqualToAnchor_constant(&view.bottomAnchor(), margin),
    ] {
        constraint.setActive(true);
    }
}

/// The standard menus, so ⌘Q, ⌘W, ⌘H and ⌘M work as in any other app.
fn main_menu(mtm: MainThreadMarker) -> Retained<NSMenu> {
    let item = |title: &str, action: Sel, key: &str| unsafe {
        NSMenuItem::initWithTitle_action_keyEquivalent(
            mtm.alloc(),
            &NSString::from_str(title),
            Some(action),
            &NSString::from_str(key),
        )
    };
    let submenu = |title: &str, items: Vec<Retained<NSMenuItem>>| {
        let menu = NSMenu::initWithTitle(mtm.alloc(), &NSString::from_str(title));
        for entry in items {
            menu.addItem(&entry);
        }
        let holder = NSMenuItem::new(mtm);
        holder.setSubmenu(Some(&menu));
        holder
    };

    let bar = NSMenu::new(mtm);
    bar.addItem(&submenu(
        "Lagwatch",
        vec![
            item("About Lagwatch", sel!(orderFrontStandardAboutPanel:), ""),
            NSMenuItem::separatorItem(mtm),
            item("Hide Lagwatch", sel!(hide:), "h"),
            NSMenuItem::separatorItem(mtm),
            item("Quit Lagwatch", sel!(terminate:), "q"),
        ],
    ));
    bar.addItem(&submenu(
        "Window",
        vec![
            item("Close", sel!(performClose:), "w"),
            item("Minimize", sel!(performMiniaturize:), "m"),
        ],
    ));
    bar
}

/// Asks each process to exit (SIGTERM) so it gets a chance to clean up, then
/// forces the ones still there after a grace period: dev servers in watch mode
/// sometimes ignore the polite request.
fn stop(pids: &[u32]) -> Result<(), String> {
    let signal = |pid: u32, sig| {
        if unsafe { libc::kill(pid as i32, sig) } == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        // Already gone, which is what we wanted.
        if err.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(format!("Could not stop pid {pid}: {err}"))
        }
    };
    let alive = |pid: u32| unsafe { libc::kill(pid as i32, 0) } == 0;

    let mut errors: Vec<String> = pids.iter().filter_map(|&p| signal(p, libc::SIGTERM).err()).collect();
    let deadline = Instant::now() + STOP_GRACE;
    while pids.iter().any(|&p| alive(p)) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(100));
    }
    for &pid in pids.iter().filter(|&&p| alive(p)) {
        errors.extend(signal(pid, libc::SIGKILL).err());
    }
    match errors.len() {
        0 => Ok(()),
        1 => Err(errors.remove(0)),
        n => Err(format!("{} (and {} more)", errors[0], n - 1)),
    }
}

fn auto_close_path() -> Option<PathBuf> {
    let home = PathBuf::from(std::env::var_os("HOME")?);
    Some(home.join("Library/Application Support/lagwatch/auto_close"))
}

fn load_auto_close() -> bool {
    auto_close_path()
        .and_then(|path| fs::read_to_string(path).ok())
        .is_none_or(|text| text.trim() != "0")
}

fn save_auto_close(on: bool) {
    let Some(path) = auto_close_path() else { return };
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let _ = fs::write(path, if on { "1" } else { "0" });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_forces_processes_that_ignore_sigterm() {
        let mut stubborn = std::process::Command::new("/bin/sh")
            .args(["-c", "trap '' TERM; while :; do sleep 0.1; done"])
            .spawn()
            .unwrap();
        let mut polite = std::process::Command::new("/bin/sleep").arg("30").spawn().unwrap();
        thread::sleep(Duration::from_millis(200));

        let started = Instant::now();
        stop(&[stubborn.id(), polite.id()]).unwrap();
        assert!(started.elapsed() >= STOP_GRACE, "gave up waiting too early");
        assert!(stubborn.wait().unwrap().code().is_none());
        assert!(polite.wait().unwrap().code().is_none());
    }

    #[test]
    fn stopping_a_gone_process_is_fine() {
        let mut gone = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let pid = gone.id();
        gone.wait().unwrap();
        assert!(stop(&[pid]).is_ok());
    }
}
