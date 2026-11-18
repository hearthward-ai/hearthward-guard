#!/usr/bin/env python3
"""M2: prompt-reading (prefill) speed at given depths. Standard library only.

Method: raw /completion with a synthetic prompt of the target size, n_predict 16, cache_prompt false, temperature 0;
read timings.prompt_per_second and prompt_n from the server. --runs per depth, report the median.

usage: python prefill_probe.py --base-url http://127.0.0.1:8080 --label L --config C --out r.jsonl
         [--ctx 8000,32000,64000,120000] [--runs 3]
"""
import argparse, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as C


def text_of(srv, target, seed):
    turns = C.filler()
    parts, tok, i = [], 0, seed
    cost = {}
    while tok < target:
        t = turns[i % len(turns)]
        k = i % len(turns)
        if k not in cost:
            cost[k] = srv.ntok(t["user"] + "\n" + t["assistant"]) + 4
        parts.append(f"[{i}] " + t["user"] + "\n" + t["assistant"])
        tok += cost[k]
        i += 1
    return "\n\n".join(parts)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:8080")
    ap.add_argument("--label", required=True)
    ap.add_argument("--config", default="default")
    ap.add_argument("--out", required=True)
    ap.add_argument("--ctx", default="8000,32000,64000,120000")
    ap.add_argument("--runs", type=int, default=3)
    a = ap.parse_args()
    srv, res = C.Server(a.base_url), C.Results(a.out, a.label, a.config)
    n_ctx = (srv.props().get("default_generation_settings") or {}).get("n_ctx") or 10 ** 9
    for ctx in [int(x) for x in a.ctx.split(",")]:
        if ctx + 64 > n_ctx:
            res.emit("prefill_skipped", ctx, "tok", ctx=ctx, why=f"server n_ctx {n_ctx}")
            continue
        vals = []
        for k in range(a.runs):
            if C.stop_requested():
                sys.exit(4)
            prompt = text_of(srv, ctx, seed=k * 7)
            C.tag(f"prefill {ctx}")
            try:
                with srv.post("/completion", {"prompt": prompt, "n_predict": 16, "cache_prompt": False,
                                              "temperature": 0}) as r:
                    t = C.json.load(r)["timings"]
            finally:
                C.tag("")
            vals.append(t.get("prompt_per_second"))
            res.emit("prefill_tps", t.get("prompt_per_second"), "tok/s", ctx=ctx, run=k + 1, prompt_n=t.get("prompt_n"))
            res.emit("prefill_s", (t.get("prompt_ms") or 0) / 1000, "s", ctx=ctx, run=k + 1, prompt_n=t.get("prompt_n"))
            print(f"{a.label} {a.config} ctx {ctx} run {k + 1}: prompt_n {t.get('prompt_n')} "
                  f"{t.get('prompt_per_second', 0):.0f} tok/s", flush=True)
        res.emit("prefill_tps_median", C.median(vals), "tok/s", n=len(vals), ctx=ctx)


if __name__ == "__main__":
    main()
