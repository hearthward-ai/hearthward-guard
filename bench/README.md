# Local agent benchmark kit

How fast and how reliable is a local model as the brain of a chat agent on a consumer GPU, when the
agent's real prompt (system prompt + tool schemas + chat history) is sent on every turn?

This kit measures that against one `llama-server` (llama.cpp) that you start yourself. It needs Python 3.10+ and
nothing else (standard library only). It runs on Windows and Linux.

Results are rows of JSON (see [RESULTS-FORMAT.md](RESULTS-FORMAT.md)); `report.py` turns them into Tables 1-7.

## What each test measures

| Test | Script | Question it answers |
|---|---|---|
| m1 | `turn_bench.py` | How long until the first reply token and the first tool call or answer, on a realistic agent turn? Follow-up turn (prompt cached) and new conversation (nothing cached), English and Chinese. Optional: the server was asleep. |
| m2 | `prefill_probe.py`, `turn_bench.py --mode depth` | Prompt-reading (prefill) and writing (decode) speed at 8K, 32K, 64K and 120K tokens of context. |
| m3 | (your server's load log) + `turn_bench.py --mode depth` | Which KV-cache type and context size fit in VRAM without spilling into shared system memory. |
| m4 | `agent_bench.py` | Tool-calling success on 40 fixed tasks with mocked tool results (pick the tool, fill arguments, chain tools, answer without a tool, ignore planted instructions, long context). Strict success, schema-valid calls, steps, time. |
| m5 | `concurrency.py` | Two or three bots sharing one server: a burst (all at once) and a scripted day of messages. Queue wait, first answer, tokens/s, cache hits, errors. |
| m6 | (event rows from your own tooling) | Living with other GPU users: a background GPU workload that yields to the LLM: how long the model takes to stop and come back. |
| m7 | `powerlog.py` | GPU board power and CPU package power at 1 Hz, tagged with what was running. Wall power is not measured. |

## Quick start

1. Start one server, for example with the production recipe in `configs/production.args`. Replace `${MODEL}`,
   `${PORT}` and `${TEMPLATE}` (or drop the `--chat-template-file` line to use the model's own template). Stop
   anything else that uses the GPU.
2. Run the tests:

```
python run_all.py --base-url http://127.0.0.1:8080 --label my-model --tests m1,m2,m4,m7 \
    --server-exe <path to llama-server> --model <path to the .gguf> --args-file configs/production.args
```

3. Read `results/<date>-<label>/RESULTS.md`. The raw rows sit next to it as `*.jsonl`.

Options: `--tests m1,m2,m4,m5,m7`; `--passes 3` (m4); `--sleep-test` (m1 'asleep' case, needs a server started
with `--sleep-idle-seconds`); `--idle-minutes 10` (m7 idle power with the model loaded).

Each script also runs alone; `python <script> --help` lists its options. To compare server setups, run each setup
with its own `--config` name into the same results folder, then run `python report.py <folder>`.

## Server setups (`configs/`)

| File | What it changes |
|---|---|
| `production.args` | Full native context, one slot, `--fit` placement, a reasoning budget, idle sleep. |
| `kv-f16.args`, `kv-q8_0.args` | KV cache type for the "what fits" table; vary `-c`. |
| `manual-ncmoe.args` | `--fit off` with a manual `--n-cpu-moe N` (experts of the first N layers on the CPU). |
| `share-c1c-no-host-cache.args` | One slot without the host-RAM prompt cache (`--cache-ram 0`). |
| `share-c2-np2-kvu.args`, `share-c3-np3-kvu.args` | Two or three slots sharing one unified KV cache. |

## Prompts and tasks

- `prompts/hermes_prompt.json`: system prompt and tool schemas of
  [Hermes Agent](https://github.com/NousResearch/hermes-agent) by Nous Research (MIT licence,
  Copyright (c) 2025 Nous Research; full text in `../THIRD_PARTY_NOTICES.md`), commit `2bd378ed1b`, as a static approximation; the file lists what was left
  out and why. `tools/extract_hermes_prompt.py` rebuilds it from a Hermes checkout.
- `prompts/filler.json`: neutral synthetic chat history (English and Chinese), made by `tools/mkfiller.py`. No
  real conversations.
- `tasks/agent_tasks.json`: the 40 m4 tasks and their mocked tool results.

## Testing the kit without a GPU

`tools/stub_server.py` is a fake server that answers like llama-server with made-up timings. It checks that the
scripts and `report.py` run; its numbers mean nothing.

```
python tools/stub_server.py --port 8099
python run_all.py --base-url http://127.0.0.1:8099 --label stub --tests m1,m5 --idle-minutes 0
```

## Fair-comparison notes

- One machine, one run per night; expect about +/-5% between runs.
- `--fit` decides layer placement when the model loads. A server that loads while another program holds VRAM keeps
  fewer layers on the GPU for its whole life, so load it on a quiet GPU.
- On Windows (WDDM) a model that does not fit spills into shared system memory without an error; decode speed then
  drops sharply. Table 3 reports the spill.
- Thinking is on and the reasoning budget is part of the setup; report it with the results (`disclosure.py` does).
- Power is GPU board power (nvidia-smi) plus CPU package power (RAPL). The rest of the PC is not measured.
