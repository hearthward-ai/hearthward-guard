# Result format

Every script appends one JSON object per line (JSONL) to the file named by `--out`. `report.py <folder>` reads all
`*.jsonl` files in the folder and its sub-folders and prints Tables 1-7 as markdown.

## Measurement rows

```json
{"label": "qwen3.6-35b-a3b-ud-q4_k_m", "config_id": "prod", "metric": "ttft", "value": 1.92, "unit": "s",
 "n": 1, "ts": "2026-11-16T01:12:03-06:00", "scenario": "S1", "turn": "tool", "lang": "en", "run": 3}
```

| Field | Meaning |
|---|---|
| `label` | The model under test (`--label`). |
| `config_id` | The server setup (`--config`), for example `prod`, `f16-64k`, `C2-np2-kvu`. |
| `metric`, `value`, `unit` | One measured number. `value` is `null` when it could not be measured. |
| `n` | How many samples the value summarises (1 for a single measurement). |
| `ts` | Local time with UTC offset. |
| anything else | The cell the number belongs to (scenario, context size, bot count, task id, ...). |

### Metrics per script

| Script | Metrics | Cell fields |
|---|---|---|
| `turn_bench.py` (turn, sleep) | `ttft` first token (thinking included), `t_answer` first answer text or tool call, `total`, `prompt_n` tokens read, `cache_n` tokens reused from the cache, `prompt_tps`, `gen_n`, `gen_tps`, `wall_tps`, `tool_ok` (tool turns) | `mode`, `scenario` (S1 follow-up cached, S2 new conversation, S3 server asleep), `turn` (tool/answer), `lang`, `run`, `history_tokens`, `thinking` |
| `turn_bench.py --mode depth` | same as above | `mode`, `ctx` (total prompt size), `lang`, `run` |
| `prefill_probe.py` | `prefill_tps`, `prefill_s` per run; `prefill_tps_median`; `prefill_skipped` when the server context is too small | `ctx`, `run`, `prompt_n` |
| `agent_bench.py` | `task_ok` per task; per pass `agent_success` (with `ci95`), `agent_schema_valid`, `agent_mean_steps`, `agent_s_per_finished`; `agent_success_all` over all passes | `task`, `cat`, `lang`, `pass_no`, `steps` |
| `concurrency.py` | per request `ttft`, `t_answer`, `total`, `queue_wait`, `prompt_n`, `cache_n`, `cache_hit`, `gen_n`, `gen_tps`; per cell `*_p50`, `*_p95`, `cache_hit_pct`, `gen_tps_each_p50`, `gen_tps_aggregate`, `errors`; `error` rows | `bots`, `pattern` (burst/day), `bot`, `kind` (turn or the small helper calls a bot makes) |
| fit runs (Table 3) | `fit_loaded`, `fit_vram_gb`, `fit_proc_vram_gb`, `fit_shared_gb` (spill), `fit_ram_gb`, `fit_spill`, `fit_load_s`, `fit_n_ctx`, `fit_gen_tps`; `spill`, `desktop_vram_gb` | `kv`, `ctx`, `ncmoe` (manual offload rows) |
| events (Table 6) | `event_s` | `event` (for example `game_start_to_model_stopped`, `game_end_to_model_ready`, `request_to_gpu_job_yields`), `source` |

Agent task categories: `pick` (choose the right tool), `args` (fill arguments correctly), `chain` (use one tool's
result in the next call), `notool` (answer without a tool), `inject` (ignore instructions planted in a tool result),
`long` (the same at ~32K context).

## Power rows (`power*.jsonl`)

```json
{"t": 1763277123.0, "tag": "turn S1 en 2", "gpu_w": 142.3, "vram_mib": 10840, "gpu_util": 97, "sm_mhz": 2790, "cpu_w": 61.5}
```

One row per second. `tag` says what was running (written by the scripts through the file in `BENCH_TAG_FILE`):
`turn ...`, `depth ...`, `prefill ...`, `agent ...`, `conc ...`, `idle awake`, `idle asleep`, `load <config>`, or empty.
`cpu_w` is CPU package power (RAPL); it is `null` where the counter is not available.

## disclosure.json

Hardware (GPU, VRAM, PCIe link, CPU, RAM, OS), software (llama.cpp build, driver, CUDA), the model file name and
sha256, the full server flag line with paths cut to file names, and the chat template (built-in, or the name of a custom template file). No
paths, user names or host names.

## Tables made by report.py

| Table | Built from |
|---|---|
| 1 Waiting for a reply | `turn_bench` turn/sleep rows (S1-S3) plus S4 rows (asleep and a background GPU job has to yield first): P50/P95 of `ttft` and `t_answer`, median `total` and `prompt_n`. |
| 2 Context depth | `prefill_tps` and depth-mode `gen_tps` per server setup and context, with the spill flag. |
| 3 What fits in 12 GB | `fit_*` rows: VRAM, host RAM, spill and writing speed per KV type and context. |
| 4 Tool calling | `task_ok` per category and server setup: schema-valid %, strict success % with a 95% Wilson interval, steps, seconds per finished task. |
| 5 Several bots | `concurrency.py` cell rows. |
| 6 Other GPU users (background workload) | `event_s` rows: median, worst, N. |
| 7 Power | power rows grouped by tag; Wh per bot turn integrates each `turn ...` segment; USD/month uses `--price` (default 0.15 USD/kWh). Wall power is not measured. |
