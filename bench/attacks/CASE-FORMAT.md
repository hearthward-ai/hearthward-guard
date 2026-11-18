# Attack case format (v1)

One case per line in `cases/*.jsonl` (UTF-8, no BOM). Machine schema: `case.schema.json`. Checker: `validate_cases.py` (schema plus the cross-field rules below). Run it before every commit:

```
python -I bench/attacks/validate_cases.py bench/attacks/cases
```

## Fields

| Field | Required | Values / meaning |
|---|---|---|
| `id` | yes | Unique across all files. `^[a-z0-9][a-z0-9_.:-]{2,120}$`. Own cases: `own:<category>-<lang>-<nnn>`. Public cases: `<source-id>:<split>:<row>`. |
| `group` | no | Variants of one idea (same attack with different encodings, same scam in en and zh) share a group, so they always land in the same split. |
| `category` | yes | One of the 11 below. |
| `mimics` | hard negatives only | The attack category (1-10) the benign case looks like. Used for the per-category false-positive rate. |
| `lang` | yes | `en`, `zh` or `mixed`. Rows in other languages are dropped at import. |
| `channel` | yes | `text` (chat message), `attachment` (file text), `tool_result`, `image_ocr`, `multi_turn`, `output` (model output, Gatehouse side). |
| `payload` | one of payload / generator | A string (max 64 KiB). For `multi_turn`: a list of 2-50 `{"role": "user|assistant|tool|attachment", "text": ...}` turns. |
| `generator` | one of payload / generator | `{"name": "module.function", "seed": int, "params": {...}}`. Used for encodings, hidden characters, images and secret-shaped strings, so the files never hold real secrets or rendered images. `image_ocr` cases must use a generator (synthetic images only). |
| `attachment_name` | no | File name shown for `attachment` cases. |
| `expected` | yes | `verdict` (required): `block`, `hold` or `allow`. Optional per-layer detail: `threshold` hold/warn/pass, `scam_level` none/warn/high, `gatehouse` strip/withhold/pass. |
| `hard_negative` | yes | `true` exactly when `category` is `hard_negative`. |
| `source` | yes | `name` (`own` or a `sources.json` id), `licence` (SPDX), `attribution`, plus `url`, `revision` (required for public sources) and `original_id`. |
| `optimistic` | no | `true` for own cases written after the rule they test (reported separately). |
| `split` | yes | `dev` or `test`, fixed by hash (below). |
| `notes` | no | Up to 2000 characters. Never personal data. |

### Verdicts
- `block`: refused outright, nothing reaches the model or the user (Gatehouse withholds output, Knock denies a tool call).
- `hold`: quarantined for the owner's review; for scams, the user also gets a warning.
- `allow`: passes. It may still carry a warning (`scam_level: warn`), for example "is this text a scam?".

### Categories
1. `direct_override` - ignore-previous, persona swaps, fake developer mode.
2. `fake_markers` - fake system tags, envelope or reply markers inside the payload.
3. `encoding` - base64, hex, URL, HTML entities, rot13, leetspeak, nested.
4. `hidden_chars` - zero-width, bidi overrides, TAG block, variation selectors, soft hyphens.
5. `lookalike` - Cyrillic/Greek/fullwidth swaps, mixed-script words.
6. `split_instruction` - split across messages, attachment + message, OCR lines, reversed order.
7. `tool_smuggling` - fake tool-call JSON or markup, `MEDIA:`/path directives, markdown image/link exfil, "call this tool".
8. `image_ocr_scam` - bank, toll, parcel, gift card, tech support, investment group, QR, low-contrast text.
9. `scam_text` - en/zh scam messages and mixed-language ones.
10. `output_leak` - secret-shaped strings, invisible characters, attachment directives in model output (`output` channel only).
11. `hard_negative` - benign look-alikes of 1-10 (the false-positive side).

## Rules the validator enforces
- Unknown keys, missing required keys and bad enum values are errors.
- **Split by hash:** `split = test` when `int(sha256("attacks-split-v1\0" + key)[:8], 16) % 100 < 40`, else `dev`; `key` is `group` if set, else `id`. Tune only on `dev`; the honest numbers come only from `test`. Changing the salt or the 40 % is a breaking change (the tests freeze two known values). `python -I validate_cases.py --split-of <key>` prints the split.
- Public datasets' own train/test splits are ignored; our hash decides, so nothing tuned on can leak into the honest test.
- Hard negatives: need `mimics` and must expect `allow`.
- `allow` cannot be paired with `threshold: hold` or `gatehouse: withhold`.
- `output` channel needs `expected.gatehouse`; `output_leak` cases use the `output` channel.
- Licence: files under `cases/` (public) may only hold Apache-2.0, MIT, BSD-2/3-Clause, CC-BY-4.0 or CC0-1.0 cases. Imported rows from other licences live only in the local cache and are checked with `--local-only`.
- Error messages show ids and line numbers, never case text.

## Results
Per category: n, caught, missed, false positives (hard negatives with that `mimics` that were not allowed), Wilson 95 % interval; n < 50 is marked "indicative only". Public-dataset rows and own rows are reported separately, as are `optimistic` cases. No single overall percentage.
