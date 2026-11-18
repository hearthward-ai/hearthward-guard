# Guard attack test set (bench/attacks)

Test cases for the guard plugin: 11 categories, en/zh/mixed, results per category with the false-positive rate. Python standard library only, except the importer's parquet reader (pyarrow, dev-only, bench venv).

| File | What it is |
|---|---|
| `CASE-FORMAT.md` | Case format spec, verdicts, categories, hash split rule. |
| `case.schema.json` | JSON schema for one case. |
| `validate_cases.py` | Validator (schema + cross-field rules + fixed split). |
| `cases/` | Public cases: `examples.jsonl` plus own cases (`cases/own/<category>.jsonl`; coverage in `cases/own/COVERAGE.md`). |
| `../../DATASETS.md` | Public datasets used for testing: sources, licences, download steps (not included in this repo). |
| `sources.json` | Pinned URLs, revisions, sizes and hashes, approval records. |
| `fetch.py` | Downloads approved sources only, into an empty folder outside the repo, and checks hashes. |
| `import_public.py` | Fetch cache -> cases: re-checks hashes, language filter, global dedupe (label conflicts dropped), hash split, attribution per case, validation. Writes outside the repo. |
| `guard_adapter.py` | Plug-in point for the guard under test: the guard (`guard/hearthward_guard`) or a regex stub for tests. |
| `run.py` | Runs cases through the layers; per-category catch and false-positive rates (Wilson 95 %), weak-as-hold variant, per source/subset, latency per layer. |
| `generators.py` | Generator plug-in: `generate(name, seed, params)` for encodings, hidden characters, lookalikes, secret shapes, padding, malformed and benign Unicode; `render_spec()` holds the exact text of every image. Standard library only; deterministic (sha256 counter-mode stream). |
| `gen_qr.py` | Minimal QR encoder (byte mode, level M, versions 1-10) for QR scam images. Standard library only. |
| `gen_render.py` | Draws synthetic image_ocr cases (fictional brands, reserved fake values) with Pillow; records Pillow version and font hashes. |
| `generate_cases.py` | Materialises all generator cases outside the repo (`<LOCAL>/generated/`: payloads.jsonl, images/, images.jsonl, manifest.json with per-case sha256); `--check` regenerates and compares. |
| `test_*.py` | Offline tests (synthetic inputs only). |

## Local data (never in the repo)
`fetch, don't vendor`: imported public cases, results and the honest-run ledger live in `~/Hearthward-Data/attack-bench/` (override with `HEARTHWARD_BENCH_LOCAL`); the fetch cache is `~/Hearthward-Data/attack-cache/`; the bench venv (pyarrow) is `~/Hearthward-Data/bench-venv/`. Publish only case ids and results (results never contain case text). `.gitignore` also lists `local/`, `__pycache__/` and `.venv/` as a backstop; run Python with `-B` so no `__pycache__` lands in the tree.

```
python -I -B -m unittest discover -s bench/attacks -p "test_*.py"          # parquet test needs the venv
python -I -B bench/attacks/validate_cases.py bench/attacks/cases
<venv>/python -I -B bench/attacks/import_public.py --cache ~/Hearthward-Data/attack-cache
python -I -B bench/attacks/generate_cases.py [--check]                      # materialise generator cases (needs Pillow for images)
python -I -B bench/attacks/run.py                                           # pattern mode, dev split
python -I -B bench/attacks/run.py --split test --honest                     # honest run (once per guard version; see the ledger)
python -I -B bench/attacks/run.py --mode second-check --endpoint http://127.0.0.1:8080/v1 --sample 200
```

## Runner rules
- Modes: `pattern` (model-free: Threshold + window + Gatehouse) and `second-check` (adds the guard's tool-less model check; needs `--endpoint`, loopback only; stops after 5 unavailable checks in a row). Run second-check only when the shared model server is free.
- Splits: dev is for tuning. `--split test` needs `--honest`, refuses the stub guard, writes aggregates only (no per-case file) and appends to the honest-run ledger, which reports how many guard versions have seen the test split.
- Mirrors the hooks: window only when not already held, second check only raises, `weak_action` only on inbound chat/attachments, tool results not windowed. Second-check channels default to the guard config (tool results excluded); `--sc-channels` overrides.
- Not built yet (cases marked, never counted as misses): scam layer (`unscored:scam-layer-missing`), OCR (`skipped:ocr-layer-missing`), Knock (`knock: n/a`). Generator cases run through `generators.generate()` (placeholders are filled before encoding); each record carries `gen_sha256` (first 16 hex of the payload hash, same as the manifest) and the summary records the generator version and code hashes. image_ocr cases stay `skipped:ocr-layer-missing` until an OCR layer exists; it can then take `generators.generate_image()` bytes and score against the ground-truth text.
- `notes` may carry `subset=<name>`; results are broken down by it (SPML degree, AgentDojo attack template, BIPIA text/code).
