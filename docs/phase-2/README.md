# Phase 2 Design Documentation

This folder contains the design and implementation reference documents
authored during Phase 2 of the Shape-Scan TEM development effort.

These documents are reference material for the architecture, visualisation
engine, and operational framing of the toolchain. The implementation in
this repository is the source of truth for actual behaviour — where the
documents and the code disagree, the code wins.

## Index

| # | Document | Purpose |
|---|----------|---------|
| 01 | Shape-Scan Phase 2 - Chrome Subsystem + Liquid Glass Retrofit | DS-001 design system + Step 7B Chrome Subsystem spec (sparklines, radars, HUD). |
| 02 | Phase 2 Morphological Visualization Engine - Implementation Plan v1 | Original MVE plan (twin viewports, Superformula + Toroidal Markov). |
| 03 | Phase 2 Morphological Visualization Engine - Implementation Plan v4 | Refined MVE plan with renderer contract and class taxonomy. |
| 04 | Phase 2 Implementation Plan REVISED v2 | Revision of the implementation plan (intermediate iteration). |
| 05 | Phase 2 Implementation Plan REVISED v3 | Latest revision of the implementation plan. |
| 06 | Walkthrough - Shape-Scan TEM Phase 2 Finalization | End-to-end walkthrough of the finalised Phase 2 system. |
| 07 | Shape-Scan TEM - Product Codex (corrected) | Master reference covering lineage, architecture, IP differentiation, and commercialisation posture. |
| 08 | P-METIS-IEL Synthesis Report | Post-finalisation cross-module synthesis. |
| 09 | Visual Recognition Handbook - The Physics of File Morphology | Operator-facing handbook of morphological classes. |

## Notes

* The corrected Product Codex (07) supersedes any earlier revisions of the
  same document.
* Some terminology used in the documents (e.g. internal naming framework,
  protocol IDs) is intentionally not surfaced in the public README or CLI
  output. Consult the documents for the canonical framing; consult the code
  for runtime behaviour.
* Sensitive forensic briefs are kept out of this folder. See `docs/private/`
  (gitignored).
