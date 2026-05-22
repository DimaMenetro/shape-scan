# shape-scan — TEM v2.0

**Geometric threat analysis.** Measures the mathematical *shape* of a file —
entropy, microstructure, topology, and intent — to flag suspicious binaries
without relying on signatures.

> Status: `v2.0.0-alpha`. This is a research-grade triage tool, not an
> anti-virus replacement. See *Honest limits* below.

## Pipeline

```
Raw bytes
   │
   ├── TFEA   — Thermodynamic / entropy profile (Shannon, sliding window,
   │            header-vs-body mismatch, compression ratio)
   │
   ├── Markov — 256×256 byte-transition matrix; captures sequential
   │            microstructure that bulk entropy misses
   │
   ├── TCGE   — Topological Code-Graph Engine; builds a graph from
   │            byte/section relations and reports density, components,
   │            strongly-connected components, fingerprints
   │
   ├── AISE   — Axiomatic Intent Scoring; pattern-based flags for
   │            shell-exec, code-eval, network, file-manip, etc.
   │
   └── CQSF   — Cognitive Quarantine / Semantic Firewall. Combines the
                above into a numeric threat score + verdict. Only
                numeric feature vectors leave this boundary — no
                decoded strings, no reconstructed code.
```

Each stage emits a typed, serializable profile (`serde_json`) so the
results can be inspected, logged, or fed into another tool.

## Crates in this workspace

| Crate         | Path        | What it is                                           |
| ------------- | ----------- | ---------------------------------------------------- |
| `shape-scan`  | `./`        | Analysis engine + `shape-scan` CLI binary            |
| `shape-scan-ui` | `src-tauri/` | Tauri 2 desktop app (SQLite-backed scan history) |

## CLI

```bash
cargo build -p shape-scan --release
./target/release/shape-scan scan <file-or-dir>
./target/release/shape-scan entropy <file>   # TFEA only
./target/release/shape-scan shape <file>     # TCGE + Markov only
./target/release/shape-scan intent <file>    # AISE only
```

Exit codes:

- `0` — no high-risk findings
- `1` — at least one file scored high-risk
- `2` — usage / I/O error

## Desktop app (optional)

The Tauri shell in `src-tauri/` exposes the same engine through a web UI
under `ui/`. Building it requires platform-specific dependencies (Linux:
`libwebkit2gtk-4.1-dev` and friends; Windows: WebView2; macOS: Xcode CLT).
See the [Tauri prerequisites](https://tauri.app/start/prerequisites/).

Helper scripts (Windows-focused):

- `build.ps1` — build the engine + UI bundle
- `launch.bat` — start the desktop app
- `scan.ps1` — run the CLI against a path

## Build configuration

`.cargo/config.toml` pins `jobs = 1` for the workspace. This is a
deliberate workaround for an interaction between rustc's parallel codegen
and real-time file scanners on Windows (`os error 32`, see
[rust-lang/rust#94073](https://github.com/rust-lang/rust/issues/94073)).
Linux/macOS builds are unaffected but inherit the same setting.

## Honest limits

- Entropy + topology are well-known **triage signals**, not malware
  verdicts. Sophisticated payloads can tune their statistics to evade
  exactly these checks.
- The intent flags (`AISE`) are pattern-based: they tell you *that*
  byte-sequences associated with risky operations exist, not *what* the
  program will do.
- Numeric scores are calibrated against a small corpus and will drift on
  unseen file types.

Use this for triage and prioritisation; pair it with a real analyser
(YARA, sandboxing, behavioural telemetry) for verdicts.

## Design notes

The `plan-implimentation/` directory contains the working design
documents that this implementation is derived from (PDF + reference
screenshots). It is not required to build or run the tool.

## License

Dual-licensed under [MIT](./LICENSE-MIT) or [Apache-2.0](./LICENSE-APACHE),
at your option.
