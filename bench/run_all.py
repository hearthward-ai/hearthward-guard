#!/usr/bin/env python3
"""Run the benchmark against ONE llama-server you started yourself (see configs/ and README.md). Standard library only.
Stop anything else that uses the GPU first. Results: <out-dir>/*.jsonl, disclosure.json and RESULTS.md.

  m1  time to first reply: S1 follow-up (cached) and S2 new conversation, tool and answer turns, EN + 中文
      (S3 'asleep' only with --sleep-test, which needs a server started with --sleep-idle-seconds)
  m2  prompt reading speed (prefill) and writing speed at 8K/32K/64K/120K (needs a server context >= 128K)
  m4  40 agent tool-calling tasks (--passes, default 1)
  m5  two bots sharing the server (burst + scripted 8-minute day)
  m7  power log alongside everything; plus --idle-minutes of idle (model loaded) at the end

usage: python run_all.py --base-url http://127.0.0.1:8080 --label mymodel --tests m1,m2,m4 [--out-dir results/x]
         [--server-exe PATH --model PATH --args-file configs/x.args] [--passes 3] [--sleep-test] [--idle-minutes 10]
"""
import argparse, datetime, os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
PY = [sys.executable, "-X", "utf8"]


def step(args, env):
    print(">>", " ".join(os.path.basename(a) if os.path.isabs(a) else a for a in args[2:]), flush=True)
    rc = subprocess.call(PY + args[2:] if args[:2] == ["py", "kit"] else args, env=env)
    if rc not in (0,):
        print(f"   step ended with exit code {rc}", flush=True)
    return rc


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-url", default="http://127.0.0.1:8080")
    ap.add_argument("--label", required=True)
    ap.add_argument("--tests", default="m1,m2,m4")
    ap.add_argument("--out-dir")
    ap.add_argument("--config", default="default")
    ap.add_argument("--server-exe")
    ap.add_argument("--model")
    ap.add_argument("--args-file")
    ap.add_argument("--passes", type=int, default=1)
    ap.add_argument("--sleep-test", action="store_true")
    ap.add_argument("--idle-minutes", type=float, default=10)
    a = ap.parse_args()
    tests = set(a.tests.split(","))
    out = a.out_dir or os.path.join(HERE, "results", f"{datetime.date.today()}-{a.label}")
    os.makedirs(out, exist_ok=True)
    env = dict(os.environ, BENCH_TAG_FILE=os.path.join(out, "tag.txt"))
    common = ["--base-url", a.base_url, "--label", a.label, "--config", a.config]
    k = lambda name: os.path.join(HERE, name)
    o = lambda name: ["--out", os.path.join(out, name)]
    d = ["py", "kit", k("disclosure.py"), "--out", os.path.join(out, "disclosure.json")]
    for opt, v in (("--server-exe", a.server_exe), ("--model", a.model), ("--args-file", a.args_file)):
        if v:
            d += [opt, v]
    step(d, env)
    power = None
    if "m7" in tests:
        stop = os.path.join(out, "power.stop")
        if os.path.exists(stop):
            os.remove(stop)
        power = subprocess.Popen(PY + [k("powerlog.py"), "--out", os.path.join(out, "power.jsonl"),
                                       "--tag-file", env["BENCH_TAG_FILE"], "--stop-file", stop], env=env)
    try:
        if "m1" in tests:
            for cache in ("on", "off"):
                for turn in ("tool", "answer"):
                    step(["py", "kit", k("turn_bench.py")] + common + o("m1.jsonl") + ["--cache", cache, "--turn", turn], env)
            if a.sleep_test:
                step(["py", "kit", k("turn_bench.py")] + common + o("m1.jsonl") + ["--mode", "sleep", "--turn", "answer", "--runs", "3"], env)
        if "m2" in tests:
            step(["py", "kit", k("prefill_probe.py")] + common + o("m2.jsonl"), env)
            step(["py", "kit", k("turn_bench.py")] + common + o("m2.jsonl") + ["--mode", "depth", "--runs", "2"], env)
        if "m4" in tests:
            step(["py", "kit", k("agent_bench.py")] + common + o("m4.jsonl") + ["--passes", str(a.passes)], env)
        if "m5" in tests:
            step(["py", "kit", k("concurrency.py")] + common + o("m5.jsonl") + ["--bots", "2"], env)
        if "m7" in tests and a.idle_minutes > 0:
            with open(env["BENCH_TAG_FILE"], "w", encoding="utf-8") as f:
                f.write("idle awake")
            print(f">> idle {a.idle_minutes} min (power only)", flush=True)
            time.sleep(a.idle_minutes * 60)
    finally:
        if power:
            open(os.path.join(out, "power.stop"), "w").close()
            try:
                power.wait(15)
            except subprocess.TimeoutExpired:
                power.kill()
    step(["py", "kit", k("report.py"), out, "--out", os.path.join(out, "RESULTS.md")], env)


if __name__ == "__main__":
    main()
