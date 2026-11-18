#!/usr/bin/env python3
"""M1 + M2 (decode): what a bot user waits for, on a Hermes-sized turn. Standard library only.

Prompt: Hermes Agent's default system prompt + tool schemas (prompts/hermes_prompt.json), neutral synthetic chat
history (prompts/filler.json), then one new user message. Thinking on, temperature 0.6, top_p 0.95 (bot settings).

Modes
  turn   S1/S2: one bot turn on a warm server. --cache on = follow-up turn (the same prefix was just sent, so the
         server can reuse it); --cache off = new conversation (nothing reused). --turn tool|answer.
  sleep  S3: wait until /props reports is_sleeping (the server unloaded the model after --sleep-idle-seconds),
         then send one turn; the wake-up and reload are part of the measured time. Repeats --runs times.
  depth  decode speed at depth: answer turns at each --ctx (cache off), like a long chat.

Metrics (seconds unless noted): ttft (first token, thinking included), t_answer (first visible text or tool call =
what the user waits for), total, prompt_n, cache_n (tokens reused), prompt_tps, gen_tps, wall_tps, tool_ok.

usage: python turn_bench.py --base-url http://127.0.0.1:8080 --label L --config C --out results.jsonl
         [--mode turn|sleep|depth] [--cache on|off] [--turn tool|answer] [--lang en,zh] [--runs 5]
         [--history-tokens 4000] [--ctx 8000,32000] [--max-tokens 1500] [--thinking on|off] [--max-wait 900]
"""
import argparse, json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # python -I leaves the script folder off sys.path
import common as C

ASK = {
    ("tool", "en"): ["Search the web for the opening hours of the city library this Saturday.",
                     "Look up the current exchange rate from euros to US dollars, please.",
                     "Find recent reviews of the cheapest electric kettle you can find online.",
                     "Search for the train timetable from the main station to the airport tomorrow morning.",
                     "Please check the web for this week's weather warnings in my region."],
    ("tool", "zh"): ["帮我在网上查一下本周六市图书馆的开放时间。", "请查一下现在欧元兑美元的汇率。",
                     "在网上找一找最便宜的电热水壶的最新评价。", "搜索一下明天早上从火车站到机场的列车时刻表。",
                     "请上网看看这周本地区有没有天气预警。"],
    ("answer", "en"): ["In about 200 words, explain how a heat pump can move more heat than the electricity it uses.",
                       "In about 200 words, explain why the sky is blue but sunsets are red.",
                       "In about 200 words, explain what compound interest is, with one small numeric example.",
                       "In about 200 words, explain how a vaccine trains the immune system.",
                       "In about 200 words, explain why ice floats on water."],
    ("answer", "zh"): ["用大约300字解释：热泵为什么能搬运比它耗电更多的热量？", "用大约300字解释：为什么天空是蓝色的，而日落是红色的？",
                       "用大约300字解释什么是复利，并举一个简单的数字例子。", "用大约300字解释疫苗是怎样训练免疫系统的。",
                       "用大约300字解释为什么冰会浮在水面上。"],
}
LONG_ASK = {"en": "Thanks. Using everything we discussed above, write a detailed plan for next week: a day-by-day "
                  "schedule with times, what to prioritise, and three risks with how to handle each. Think it through first.",
            "zh": "谢谢。请根据上面我们聊过的所有内容，详细安排下周的计划：按天列出时间表、优先做什么，以及三个可能的风险和应对办法。请先想清楚再回答。"}


def body(system, tools, hist, user, a, cache):
    b = {"messages": [{"role": "system", "content": system}] + hist + [{"role": "user", "content": user}],
         "tools": tools, "max_tokens": a.max_tokens, "cache_prompt": cache}
    b.update(C.SAMPLING)
    b.update(C.thinking(a.thinking == "on"))
    return b


def measure(srv, res, b, cell):
    C.tag(f"turn {cell['scenario']} {cell.get('lang')} {cell.get('run')}" if cell.get("scenario")
          else f"depth {cell.get('ctx')} {cell.get('run')}")
    try:
        r = srv.chat(b)
    finally:
        C.tag("")
    t = r["timings"]
    pn, cn, gn = t.get("prompt_n"), t.get("cache_n"), t.get("predicted_n") or 0
    wall = (gn - 1) / (r["total"] - r["ttft"]) if r["ttft"] and gn > 1 and r["total"] > r["ttft"] else None
    tool_ok = bool(r["tool_calls"]) if cell.get("turn") == "tool" else None
    vals = {"ttft": (r["ttft"], "s"), "t_answer": (r["t_answer"], "s"), "total": (r["total"], "s"),
            "prompt_n": (pn, "tok"), "cache_n": (cn, "tok"), "prompt_tps": (t.get("prompt_per_second"), "tok/s"),
            "gen_n": (gn, "tok"), "gen_tps": (t.get("predicted_per_second"), "tok/s"), "wall_tps": (wall, "tok/s")}
    if tool_ok is not None:
        vals["tool_ok"] = (int(tool_ok), "bool")
    for k, (v, u) in vals.items():
        res.emit(k, v, u, **cell)
    print(json.dumps({k: (round(v, 2) if isinstance(v, float) else v) for k, (v, _) in vals.items()} | cell, ensure_ascii=False), flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-url", default="http://127.0.0.1:8080")
    ap.add_argument("--label", required=True)
    ap.add_argument("--config", default="default")
    ap.add_argument("--out", required=True)
    ap.add_argument("--mode", default="turn", choices=["turn", "sleep", "depth"])
    ap.add_argument("--cache", default="off", choices=["on", "off"])
    ap.add_argument("--turn", default="answer", choices=["tool", "answer"])
    ap.add_argument("--lang", default="en,zh")
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--history-tokens", type=int, default=4000)
    ap.add_argument("--ctx", default="8000,32000,64000,120000")
    ap.add_argument("--max-tokens", type=int, default=1500)
    ap.add_argument("--thinking", default="on", choices=["on", "off"])
    ap.add_argument("--max-wait", type=int, default=900, help="sleep mode: max seconds to wait for is_sleeping")
    a = ap.parse_args()
    srv, res = C.Server(a.base_url), C.Results(a.out, a.label, a.config)
    system, tools = C.hermes()
    base = srv.ntok(system + json.dumps(tools)) + 50
    langs = a.lang.split(",")
    if a.mode == "depth":
        for ctx in [int(x) for x in a.ctx.split(",")]:
            for k in range(a.runs):
                if C.stop_requested():
                    sys.exit(4)
                lang = langs[k % len(langs)]
                hist, _ = C.history(srv, ctx, base, lang, seed=k)
                measure(srv, res, body(system, tools, hist, LONG_ASK[lang], a, False),
                        {"mode": "depth", "ctx": ctx, "lang": lang, "run": k + 1, "turn": "answer", "thinking": a.thinking})
        return
    scen = "S3" if a.mode == "sleep" else ("S1" if a.cache == "on" else "S2")
    for lang in langs:
        hist, est = C.history(srv, base + a.history_tokens, base, lang, seed=0)
        for k in range(a.runs):
            if C.stop_requested():
                sys.exit(4)
            user = ASK[(a.turn, lang)][k % 5]
            cell = {"mode": a.mode, "scenario": scen, "turn": a.turn, "lang": lang, "run": k + 1,
                    "history_tokens": a.history_tokens, "thinking": a.thinking}
            if a.mode == "sleep":
                t0 = time.time()
                while not srv.props().get("is_sleeping"):
                    if time.time() - t0 > a.max_wait or C.stop_requested():
                        print("server did not fall asleep in time", flush=True)
                        sys.exit(4 if C.stop_requested() else 3)
                    time.sleep(5)
                cell["asleep_wait_s"] = round(time.time() - t0)
                measure(srv, res, body(system, tools, hist, user, a, True), cell)
            elif a.cache == "on":
                # prime: the same prefix + an earlier user line, so the measured turn is a follow-up
                pb = body(system, tools, hist, ASK[(a.turn, lang)][(k + 2) % 5], a, True)
                pb["max_tokens"] = 1
                srv.chat(pb)
                measure(srv, res, body(system, tools, hist, user, a, True), cell)
            else:
                measure(srv, res, body(system, tools, hist, user, a, False), cell)


if __name__ == "__main__":
    main()
