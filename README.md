# shape-scan

`shape-scan` is a small command-line tool that measures the **Shannon entropy**
and **topological shape** of files. It's intended as a triage signal during
binary analysis: files that look statistically similar to packed, encrypted, or
otherwise obfuscated content (a common malware pattern) are surfaced with a
heuristic risk score.

> **Honest claim:** `shape-scan` is **not** a malware classifier and it cannot
> make malware "impossible to get past". File entropy and byte-graph shape are
> well-known, well-studied features — sophisticated malware authors deliberately
> tune their payloads to evade exactly these checks (e.g. by stuffing English
> text or padding into otherwise random sections). Use `shape-scan` the way
> you'd use `file(1)` or `strings(1)`: as a fast, statistically-grounded signal
> that helps a human prioritise what to look at next.

## What it computes

For every file you point it at:

1. **Shannon entropy** of the whole file, in bits/byte (max 8.0).
2. **Sliding-window entropy**: per-window mean, std-dev, min/max, and the
   fraction of windows above 7.5 bits/byte (a common "looks encrypted"
   threshold).
3. **Per-section entropy** for ELF, PE, and Mach-O binaries (via `goblin`).
4. **Topological shape** of the byte stream, treated as a Markov chain over its
   bytes:
   - `|V|` — number of distinct byte values present (≤ 256)
   - `|E|` — number of distinct adjacent byte pairs (≤ 65 536)
   - **edge density** — `|E| / 65 536`, in `[0, 1]`
   - **bigram entropy** — joint Shannon entropy of the 256×256 transition
     matrix, in bits/pair
   - **conditional entropy** `H(b_{i+1} | b_i)`
   - **mean per-row entropy** ± std-dev across the rows of the transition
     matrix
   - **structural fingerprint** — a stable 64-bit hash of the quantised
     transition matrix
5. **Combined risk score** in `[0.0, 1.0]` plus a coarse `low`/`medium`/`high`
   bucket and a list of human-readable indicators explaining the score.

## Install

```sh
cargo install --path .
```

Or build a release binary:

```sh
cargo build --release
./target/release/shape-scan --help
```

## Usage

```sh
# Scan a single file
shape-scan scan ./suspect.bin

# Scan a directory recursively, only show medium-or-higher risk, JSON output
shape-scan scan ./samples -r --min-risk medium --format json

# Just the topology of one file
shape-scan shape ./suspect.bin

# Just the entropy profile, with a 1 KiB sliding window
shape-scan entropy ./suspect.bin --window 1024
```

Exit codes:

- `0` — completed; no high-risk files found
- `1` — completed; at least one high-risk file found
- `2` — error (bad path, I/O failure, etc.)

## How the score is composed

The score is a **weighted sum of independent indicators**, each clamped so no
single feature can dominate:

| Indicator                                                      | Weight |
|----------------------------------------------------------------|--------|
| Whole-file entropy ≥ 7.5 bits/byte                             | +0.35  |
| Whole-file entropy 7.0–7.5                                     | +0.15  |
| ≥ 50% of sliding windows above 7.5 bits/byte                   | +0.20  |
| Window-entropy std-dev ≥ 1.5                                   | +0.05  |
| Bigram-graph edge density ≥ 0.85                               | +0.15  |
| Conditional entropy ≥ 7.5 bits/byte                            | +0.10  |
| ELF/PE/Mach-O section ≥ 256 B with entropy ≥ 7.5 (max once)    | +0.15  |
| Files smaller than 1 KiB get the score scaled by 0.4           | —      |

Buckets: `< 0.45` → `low`, `< 0.75` → `medium`, otherwise `high`.

## Use it as a library

The crate also exposes a small library API:

```rust
use shape_scan::{scan_path, RiskLevel};

let report = scan_path(std::path::Path::new("suspect.bin"))?;
println!("{:?}", report.risk_level);
for ind in &report.indicators {
    println!("- {ind}");
}
```

## License

Dual-licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.
