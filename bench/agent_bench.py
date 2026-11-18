#!/usr/bin/env python3
"""M4: can the model drive a Hermes-style agent? Standard library only.

Each task (tasks/agent_tasks.json) runs as a short agent loop: Hermes system prompt + tool schemas, the user message,
then up to max_steps model calls. Tool calls are never executed: a mock returns the task's canned result.
Thinking on, temperature 0.6, top_p 0.95 (bot settings), one tool call per step.

Five checks per task, all must pass for a strict success:
  choice    first action is right (an expected tool, or no tool / ask back when that is right)
  args      the calls carry the right arguments (task regexes)
  schema    every call names a real tool, parses as a JSON object, has the required keys, no unknown keys,
            right basic types and enum values
  finished  required tool chain done in order and a final text reply (matching the task's answer regex) within max_steps
  safe      no forbidden tool, argument or text (prompt injection, risky action without asking)

Rows: per task (task_ok, check_*, steps, seconds) and a summary per pass and overall (success % with Wilson 95% CI,
schema-valid % of calls, mean steps, seconds per finished task).
usage: python agent_bench.py --base-url URL --label L --config C --out r.jsonl [--passes 1] [--pass-offset 0] [--only P01,C*] [--max-tokens 2048]
"""
import argparse, fnmatch, json, os, re, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common as C

TYPES = {"string": str, "integer": int, "number": (int, float), "boolean": bool, "array": list, "object": dict}


def schema_errors(call, schemas):
    s = schemas.get(call["name"])
    if s is None:
        return ["unknown tool"]
    try:
        args = json.loads(call["arguments"] or "{}")
    except ValueError:
        return ["arguments not JSON"]
    if not isinstance(args, dict):
        return ["arguments not an object"]
    p = s.get("parameters") or {}
    props, errs = p.get("properties") or {}, []
    for k in p.get("required") or []:
        if k not in args:
            errs.append(f"missing {k}")
    for k, v in args.items():
        if k not in props:
            errs.append(f"unknown key {k}")
            continue
        t = props[k].get("type")
        if t in TYPES and not (isinstance(v, TYPES[t]) and not (t in ("integer", "number") and isinstance(v, bool))):
            errs.append(f"{k} not {t}")
        if props[k].get("enum") and v not in props[k]["enum"]:
            errs.append(f"{k} not in enum")
    return errs


def as_text(v):
    return v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)


def args_of(call):
    try:
        a = json.loads(call["arguments"] or "{}")
        return a if isinstance(a, dict) else {}
    except ValueError:
        return {}


def mock_result(task, call):
    m = (task.get("mock") or {}).get(call["name"])
    if isinstance(m, list):
        for r in m:
            if re.search(r["if"], call["arguments"] or ""):
                return r["then"]
        return '{"ok": true}'
    return m if m is not None else '{"ok": true}'


def grade(task, calls, final, steps, max_steps, schemas):
    names = [c["name"] for c in calls]
    first = task.get("first", [])
    if task.get("clarify"):
        choice = (not calls or names[0] == "clarify") and (bool(calls) or "?" in final or "？" in final)
    elif not first:
        choice = not calls
    else:
        choice = bool(calls) and names[0] in first
    spec = task.get("args") or {}
    args_ok = True
    if spec:
        hit = [t for t in spec if t in names]
        args_ok = bool(hit)
        for t in hit:
            good = False
            for c in calls:
                if c["name"] != t:
                    continue
                a = args_of(c)
                ok = True
                for k, rx in spec[t].items():
                    v = as_text(a.get(k, ""))
                    for r in (rx if isinstance(rx, list) else [rx]):
                        ok = ok and bool(re.search(r, v))
                good = good or ok
            args_ok = args_ok and good
    schema_ok = all(not schema_errors(c, schemas) for c in calls)
    pos, chain_ok = 0, True
    for want in task.get("chain", []):
        alts = want.split("|")
        while pos < len(names) and names[pos] not in alts:
            pos += 1
        chain_ok = chain_ok and pos < len(names)
        pos += 1
    finished = bool(final.strip()) and steps <= max_steps and chain_ok and \
        (not task.get("answer") or bool(re.search(task["answer"], final)))
    allargs = " ".join(c["arguments"] or "" for c in calls)
    safe = not any(n in task.get("forbid_tools", []) for n in names) and \
        not (task.get("forbid_args") and re.search(task["forbid_args"], allargs)) and \
        not (task.get("forbid_text") and re.search(task["forbid_text"], final))
    checks = {"choice": choice, "args": args_ok, "schema": schema_ok, "finished": finished, "safe": safe}
    return checks, all(checks.values())


def run_task(srv, task, system, tools, max_steps, max_tokens, thinking=True):
    hist = []
    if task.get("history_tokens"):
        base = srv.ntok(system + json.dumps(tools)) + 50
        hist, _ = C.history(srv, task["history_tokens"], base, task.get("lang", "en"), seed=sum(map(ord, task["id"])))
    msgs = [{"role": "system", "content": system}] + hist + [{"role": "user", "content": task["user"]}]
    calls, final, steps, t0 = [], "", 0, time.perf_counter()
    while steps < max_steps:
        steps += 1
        b = {"messages": msgs, "tools": tools, "max_tokens": max_tokens, "cache_prompt": True}
        b.update(C.SAMPLING)
        b.update(C.thinking(thinking))
        r = srv.chat(b)
        if not r["tool_calls"]:
            final = r["content"] or ""
            break
        tc = []
        for i, c in enumerate(r["tool_calls"]):
            c = dict(c, id=c.get("id") or f"call_{steps}_{i}")
            calls.append(c)
            tc.append({"id": c["id"], "type": "function", "function": {"name": c["name"], "arguments": c["arguments"] or "{}"}})
        msgs.append({"role": "assistant", "content": r["content"] or "", "tool_calls": tc})
        for c in tc:
            msgs.append({"role": "tool", "tool_call_id": c["id"], "content": mock_result(task, {"name": c["function"]["name"], "arguments": c["function"]["arguments"]})})
    return calls, final, steps, time.perf_counter() - t0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-url", default="http://127.0.0.1:8080")
    ap.add_argument("--label", required=True)
    ap.add_argument("--config", default="default")
    ap.add_argument("--out", required=True)
    ap.add_argument("--passes", type=int, default=1)
    ap.add_argument("--pass-offset", type=int, default=0, help="number passes from offset+1 (a run split into steps)")
    ap.add_argument("--only", default="", help="comma list of task ids or globs")
    ap.add_argument("--max-tokens", type=int, default=2048)
    ap.add_argument("--tasks", default=os.path.join(C.HERE, "tasks", "agent_tasks.json"))
    a = ap.parse_args()
    with open(a.tasks, encoding="utf-8") as f:
        spec = json.load(f)
    tasks = spec["tasks"]
    if a.only:
        pats = a.only.split(",")
        tasks = [t for t in tasks if any(fnmatch.fnmatch(t["id"], p) for p in pats)]
    srv, res = C.Server(a.base_url), C.Results(a.out, a.label, a.config)
    system, tools = C.hermes()
    schemas = {t["function"]["name"]: t["function"] for t in tools}
    allk = alln = 0
    for p in range(a.pass_offset + 1, a.pass_offset + a.passes + 1):
        k = calls_n = calls_ok = 0
        steps_all, fin_s = [], []
        for t in tasks:
            if C.stop_requested():
                sys.exit(4)
            C.tag(f"agent {t['id']}")
            try:
                calls, final, steps, secs = run_task(srv, t, system, tools, spec.get("max_steps", 6), a.max_tokens)
            finally:
                C.tag("")
            checks, ok = grade(t, calls, final, steps, spec.get("max_steps", 6), schemas)
            k += ok
            calls_n += len(calls)
            calls_ok += sum(1 for c in calls if not schema_errors(c, schemas))
            steps_all.append(steps)
            if checks["finished"]:
                fin_s.append(secs)
            res.emit("task_ok", int(ok), "bool", task=t["id"], cat=t["cat"], lang=t["lang"], pass_no=p, steps=steps,
                     seconds=round(secs, 2), tools_called=[c["name"] for c in calls],
                     **{"check_" + c: int(v) for c, v in checks.items()})
            print(f"pass {p} {t['id']}: {'OK ' if ok else 'BAD'} {checks} steps {steps} {secs:.1f}s", flush=True)
        lo, hi = C.wilson(k, len(tasks))
        res.emit("agent_success", k / len(tasks) if tasks else None, "ratio", n=len(tasks), pass_no=p, ci95=[lo, hi])
        res.emit("agent_schema_valid", calls_ok / calls_n if calls_n else None, "ratio", n=calls_n, pass_no=p)
        res.emit("agent_mean_steps", sum(steps_all) / len(steps_all) if steps_all else None, "steps", n=len(steps_all), pass_no=p)
        res.emit("agent_s_per_finished", sum(fin_s) / len(fin_s) if fin_s else None, "s", n=len(fin_s), pass_no=p)
        allk, alln = allk + k, alln + len(tasks)
    lo, hi = C.wilson(allk, alln)
    res.emit("agent_success_all", allk / alln if alln else None, "ratio", n=alln, passes=a.passes, ci95=[lo, hi])
    print(f"strict success {allk}/{alln}", flush=True)


if __name__ == "__main__":
    main()
