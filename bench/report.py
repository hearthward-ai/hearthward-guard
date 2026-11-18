#!/usr/bin/env python3
"""JSONL results -> markdown Tables 1-7 (see RESULTS-FORMAT.md). Standard library only.
usage: python report.py <results folder> [--out RESULTS.md] [--price 0.15] [--turns-per-day 100]
Reads every *.jsonl in the folder: measurement rows ({label, config_id, metric, value, ...}) and power rows
({t, tag, gpu_w, cpu_w, ...}, files named power*.jsonl). Optional disclosure.json is printed first."""
import argparse, glob, json, os, sys
from collections import defaultdict
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as C


def f(v, d=1):
    return "-" if v is None else (f"{v:.{d}f}" if isinstance(v, (int, float)) else str(v))


def table(head, rows):
    out = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out) + "\n"


def vals(rows, **kw):
    return [r["value"] for r in rows if all(r.get(k) == v for k, v in kw.items()) and r["value"] is not None]


def t1(R):
    rows = []
    for scen, name in (("S1", "Follow-up turn (prompt cached)"), ("S2", "New conversation (nothing cached)"),
                       ("S3", "Server was asleep (model unloaded)"), ("S4", "Asleep + background GPU job yields")):
        for turn in ("tool", "answer", "short"):
            tt, ta, tot = (vals(R, scenario=scen, turn=turn, metric=m) for m in ("ttft", "t_answer", "total"))
            if not ta and not tt:
                continue
            pn = vals(R, scenario=scen, turn=turn, metric="prompt_n")
            rows.append([f"{name}, {turn} turn", f"{f(C.pct(tt, 50))} / {f(C.pct(tt, 95))} s",
                         f"{f(C.pct(ta, 50))} / {f(C.pct(ta, 95))} s", f"{f(C.pct(tot, 50))} s",
                         f"{f(C.median(pn), 0)}", str(len(ta or tt))])
    return table(["Situation", "First token P50 / P95", "First answer or tool call P50 / P95", "Full turn P50",
                  "Prompt tokens read (median)", "N"], rows)


def t2(R):
    """One row per (server setup, depth) for every setup that has prefill rows (fit-matrix depth runs stay in Table 3)."""
    cfgs = sorted({r["config_id"] for r in R if r["metric"] == "prefill_tps"})
    rows = []
    for cfg in cfgs:
        sp = [r for r in R if r["metric"] == "spill" and r["config_id"] == cfg]
        ctxs = sorted({r.get("ctx") for r in R if r["config_id"] == cfg and r.get("ctx") and
                       (r["metric"] == "prefill_tps" or (r["metric"] == "gen_tps" and r.get("mode") == "depth"))})
        for c in ctxs:
            pt = vals(R, metric="prefill_tps", ctx=c, config_id=cfg)
            ps = vals(R, metric="prefill_s", ctx=c, config_id=cfg)
            g = vals(R, metric="gen_tps", ctx=c, mode="depth", config_id=cfg)
            rows.append([cfg, f"{c // 1000}K", f(C.median(pt), 0), f"{f(C.median(ps))} s", f(C.median(g)),
                         ("no" if not any(r["value"] for r in sp) else "YES") if sp else "-", f"{len(pt)} / {len(g)}"])
    return table(["Server setup", "Context", "Prompt reading tok/s", "Time to read it", "Writing tok/s", "Spill?",
                  "N (prefill / decode)"], rows)


def klabel(c):
    return f"{c // 1024}K" if c % 1024 == 0 else f"{c // 1000}K"


def t3(R):
    fit = [r for r in R if r["metric"].startswith("fit_")]
    kvs = sorted({r.get("kv") for r in fit if r.get("kv")})
    ctxs = sorted({r.get("ctx") for r in fit if r.get("ctx")})
    rows = []
    for kv in kvs:
        line = [kv]
        for c in ctxs:
            def one(m):
                v = vals(fit, kv=kv, ctx=c, metric=m)
                return v[-1] if v else None
            if one("fit_loaded") is None:
                line.append("")
                continue
            if not one("fit_loaded"):
                line.append("did not load")
                continue
            line.append(f"{f(one('fit_vram_gb'))} GB / {f(one('fit_ram_gb'))} GB / "
                        f"{'spill' if one('fit_spill') else 'no spill'} / {f(one('fit_gen_tps'))} tok/s")
        rows.append(line)
    extra = [r for r in R if r["metric"] == "desktop_vram_gb"]
    note = f"\nDesktop VRAM on this GPU before loads: {f(C.median([r['value'] for r in extra]))} GB.\n" if extra else ""
    return table(["KV cache"] + [klabel(c) for c in ctxs], rows) + \
        "Cells: VRAM in use / host RAM of the server / spill into shared memory / writing tok/s at ~8K depth (less when the context is smaller).\n" + note


def t4(R):
    tasks = [r for r in R if r["metric"] == "task_ok"]
    rows = []
    cfgs = sorted({r["config_id"] for r in tasks})
    for cfg, cat in [(c, k) for c in cfgs for k in ["pick", "args", "chain", "notool", "inject", "long", None]]:
        sel = [r for r in tasks if r["config_id"] == cfg and (cat is None or r.get("cat") == cat)]
        if not sel:
            continue
        k = sum(r["value"] for r in sel)
        lo, hi = C.wilson(k, len(sel))
        fin = [r["seconds"] for r in sel if r.get("check_finished")]
        rows.append([cfg, cat or "**all**", str(len(sel)), f(100 * sum(r.get("check_schema", 0) for r in sel) / len(sel), 0),
                     f"{f(100 * k / len(sel), 0)} ({f(100 * lo, 0)}-{f(100 * hi, 0)})",
                     f(sum(r["steps"] for r in sel) / len(sel)), f(sum(fin) / len(fin) if fin else None)])
    sv = vals(R, metric="agent_schema_valid")
    note = f"\nSchema-valid tool calls over all calls: {f(100 * C.median(sv), 0)} % (median of passes).\n" if sv else ""
    return table(["Server setup", "Category", "Attempts", "Schema-valid tasks %", "Strict success % (95% CI)", "Avg steps",
                  "Seconds per finished task"], rows) + note


def t5(R):
    keys = sorted({(r["config_id"], r.get("bots"), r.get("pattern")) for r in R if r["metric"] == "t_answer_p50"},
                  key=lambda k: (k[1] or 0, k[0], k[2] or ""))
    rows = []
    for cfg, bots, pat in keys:
        def one(m, **kw):
            v = [r["value"] for r in R if r["metric"] == m and r["config_id"] == cfg and r.get("bots") == bots and
                 r.get("pattern") == pat and all(r.get(a) == b for a, b in kw.items())]
            return v[-1] if v else None
        rows.append([str(bots), cfg, pat, f"{f(one('t_answer_p50'))} / {f(one('t_answer_p95'))} s", f"{f(one('queue_wait_p95'))} s",
                     f"{f(one('gen_tps_each_p50'))} / {f(one('gen_tps_aggregate'))}", f(one("cache_hit_pct", kind="turn"), 0),
                     f(one("errors"), 0)])
    return table(["Bots", "Server setup", "Load", "First answer P50 / P95", "Queue wait P95", "Writing tok/s each / total",
                  "Cache hit %", "Errors"], rows)


def t6(R):
    ev = defaultdict(list)
    for r in R:
        if r["metric"] == "event_s" and r["value"] is not None:
            ev[r.get("event")].append(r["value"])
    names = [("game_start_to_model_stopped", "Game starts -> model stopped"), ("game_end_to_model_ready", "Game ends -> model ready"),
             ("request_to_gpu_job_yields", "Request -> background job yields"), ("idle_to_gpu_job_resumes", "Idle -> background job resumes")]
    rows = [[n, f(C.median(ev[k])), f(max(ev[k]) if ev[k] else None), str(len(ev[k]))] for k, n in names if ev[k]]
    return table(["Event", "Median s", "Worst s", "N"], rows)


def t7(P, price, tpd):
    groups = defaultdict(list)
    for p in P:
        tag = p.get("tag") or ""
        g = ("idle, model asleep" if tag.startswith("idle asleep") else "idle, model loaded" if tag.startswith("idle awake")
             else "hold-off helper busy (keeps the background GPU job paused)" if tag.startswith("keeper") else "prefill" if tag.startswith("prefill")
             else "generation (bot turn)" if tag.startswith("turn") else "2+ bots" if tag.startswith("conc") else None)
        if g:
            groups[g].append(p)
    seg, last, turns = [], None, []
    for p in P:   # Wh per turn: integrate each contiguous 'turn ...' segment (1 row = 1 s)
        tag = p.get("tag") or ""
        if tag.startswith("turn"):
            if tag != last:
                seg = []
                turns.append(seg)
            seg.append((p.get("gpu_w") or 0) + (p.get("cpu_w") or 0))
        last = tag
    wh_turn = C.median([sum(s) / 3600 for s in turns if s])
    rows = []
    for g in ["idle, model asleep", "idle, model loaded", "prefill", "generation (bot turn)", "2+ bots", "hold-off helper busy (keeps the background GPU job paused)"]:
        if g not in groups:
            continue
        gw = C.median([p["gpu_w"] for p in groups[g]])
        cw = C.median([p["cpu_w"] for p in groups[g]])
        month = ((gw or 0) + (cw or 0)) * 24 * 30 / 1000 * price if g.startswith("idle") else None
        rows.append([g, f(gw), f(cw), f(wh_turn, 2) if g.startswith("generation") else "-", f(month, 2), str(len(groups[g]))])
    note = ""
    if wh_turn is not None:
        note = (f"\nAt {tpd} bot turns a day the turns add about {f(wh_turn * tpd * 30 / 1000 * price, 2)} USD/month "
                f"on top of idle (GPU + CPU package only, {price} USD/kWh; wall power not measured).\n")
    return table(["State", "GPU W (median)", "CPU package W (median)", "Wh per bot turn", "USD/month 24/7", "Seconds logged"], rows) + note


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("folder")
    ap.add_argument("--out")
    ap.add_argument("--price", type=float, default=0.15)
    ap.add_argument("--turns-per-day", type=int, default=100)
    a = ap.parse_args()
    R, P = [], []
    for p in sorted(glob.glob(os.path.join(a.folder, "**", "*.jsonl"), recursive=True)):
        rows = C.read_rows([p])
        (P if os.path.basename(p).startswith("power") else R).extend(rows)
    R = [r for r in R if "metric" in r]
    md = ["# Results\n"]
    dp = os.path.join(a.folder, "disclosure.json")
    if not os.path.exists(dp):   # several runs in sub-folders: show the first run's setup
        dp = next(iter(sorted(glob.glob(os.path.join(a.folder, "**", "disclosure.json"), recursive=True))), dp)
    if os.path.exists(dp):
        md.append("## Setup\n```json\n" + open(dp, encoding="utf-8").read().strip() + "\n```\n")
    for title, body in (("Table 1: Waiting for a reply (one bot, Hermes prompt + tools, thinking on)", t1(R)),
                        ("Table 2: Context depth", t2(R)), ("Table 3: What fits in 12 GB", t3(R)),
                        ("Table 4: Tool calling (fixed tasks)", t4(R)), ("Table 5: Several bots on one server", t5(R)),
                        ("Table 6: Sharing the PC with games and a background GPU job", t6(R)),
                        ("Table 7: Power (GPU + CPU package measured; rest of the PC not measured)", t7(P, a.price, a.turns_per_day))):
        md.append(f"## {title}\n\n{body}")
    text = "\n".join(md)
    if a.out:
        with open(a.out, "w", encoding="utf-8", newline="\n") as fo:
            fo.write(text)
    print(text)


if __name__ == "__main__":
    main()
