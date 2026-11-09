# Lagwatch

A small native macOS app that tells you **why your Mac feels slow** and lets you fix it in one click.

It rescans every few seconds and shows a card for each problem it finds:

- **Forgotten dev servers.** Bun, Node, Deno and workerd processes left running after their terminal closed, the same `dev` command running twice, or servers that have been up for over a week. They are grouped by project and the whole process tree can be stopped at once. These usually sit idle in swap, so CPU and memory monitors miss them.
- **CPU hogs.** Processes that have averaged more than half a core over their lifetime, including orphans whose parent is gone.
- **Memory pressure and swap.** Reported when macOS is struggling, with a hint about what to close.
- **Piles of helpers.** Many processes with the same name using a lot of memory, broken down by the app responsible for them (for example `WebContent` processes from Safari versus other apps).

Memory is measured as the **footprint** (what Activity Monitor shows), which includes compressed and swapped-out pages, not the resident size.

Each card can list the processes involved. Lagwatch can close itself once everything it flagged has been fixed and has stayed fixed.

## Install

1. Download `Lagwatch-<version>-macos-arm64.zip` from the [latest release](../../releases/latest) and unzip it.
2. Move `Lagwatch.app` to `/Applications`.
3. The app is not notarized by Apple, so the first launch is blocked. Allow it in one of two ways:
   - Open it once, then go to **System Settings → Privacy & Security** and click **Open Anyway**, or
   - run `xattr -dr com.apple.quarantine /Applications/Lagwatch.app` in Terminal.

Requires macOS 14 (Sonoma) or later on Apple Silicon. On Intel Macs, build from source.

## Command line

```sh
/Applications/Lagwatch.app/Contents/MacOS/lagwatch check
```

prints a one-off report in the terminal.

## Build from source

You need Rust (via `rustup` or Homebrew).

```sh
./bundle.sh        # build and install into /Applications
./release.sh       # run the tests, then build a release zip in target/
cargo test
```

Lagwatch only reads process information through `ps`, `sysctl` and libproc. It needs no special permissions, sends nothing over the network, and only stops processes when you click a button.

## License

[MIT](LICENSE)
