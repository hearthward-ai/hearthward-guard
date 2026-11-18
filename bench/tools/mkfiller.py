#!/usr/bin/env python3
"""Generate prompts/filler.json: neutral, deterministic synthetic chat history (English and Simplified Chinese).

No model is needed and nothing personal is in it: everyday topics, combined from fixed sentence pieces with a seeded
random generator. It only has to look like a chat and cost realistic tokens; speed does not depend on the topic.
usage: python -I mkfiller.py [out.json] [turns_per_language]
"""
import json, os, random, sys

EN_TOPICS = ["growing tomatoes on a balcony", "planning a weekend hike", "baking sourdough bread", "fixing a squeaky door",
             "learning to juggle", "choosing a used bicycle", "brewing better coffee", "organising a bookshelf",
             "training for a 5 km run", "keeping houseplants alive in winter", "cooking a simple curry",
             "repairing a bike puncture", "planning a museum visit", "starting a stamp collection",
             "saving energy at home", "writing a short story", "photographing the night sky", "making a budget spreadsheet",
             "choosing a board game for four players", "learning basic knots"]
EN_ASK = ["Can you give me a few practical tips about {t}?", "I'm new to {t}. Where should I start?",
          "What are common mistakes people make with {t}?", "How much time should I expect to spend on {t} each week?",
          "Could you compare two simple approaches to {t}?"]
EN_BITS = ["Start small and keep notes, so you can see what works after a couple of weeks.",
           "A cheap basic setup is usually enough at first; upgrade only the part that actually limits you.",
           "Most problems come from rushing the first step, so give it a little more time than feels necessary.",
           "Check the conditions before you begin, because temperature and light change the result more than people expect.",
           "Write down a short checklist and reuse it; it saves time and avoids forgetting the boring but important parts.",
           "If something goes wrong, change one thing at a time so you can tell what made the difference.",
           "Ten focused minutes most days beat a long session once a week for building a habit.",
           "Ask someone with experience to look at your first attempt; a two-minute comment can save hours.",
           "Keep the tools clean and in one place, which sounds trivial but removes most of the friction.",
           "Plan a simple version first, then add one improvement per round once the basics feel easy.",
           "Measure rather than guess when you can: a ruler, a timer or a kitchen scale is enough.",
           "Expect the first result to be imperfect; the second and third tries are where the real learning happens."]
ZH_TOPICS = ["在阳台种番茄", "周末徒步计划", "在家烤面包", "修理吱吱响的门", "学习骑自行车", "挑选二手书架", "冲一杯好咖啡",
             "整理衣柜", "准备五公里跑步", "冬天照顾绿植", "做一道简单的咖喱", "补自行车内胎", "参观博物馆的安排",
             "开始集邮", "在家里节约用电", "写一篇短故事", "拍星空照片", "做家庭预算表", "选一款四人桌游", "学打几种常用绳结"]
ZH_ASK = ["关于{t}，你能给我几条实用的建议吗？", "我刚开始接触{t}，应该从哪里入手？", "做{t}时大家常犯哪些错误？",
          "{t}每周大概需要花多少时间？", "能比较一下{t}的两种简单做法吗？"]
ZH_BITS = ["先从小处开始，并简单记录，过两周就能看出哪些做法有效。", "一开始用便宜的基础工具就够了，只升级真正限制你的那一部分。",
           "大多数问题来自第一步太着急，所以多给它一点时间。", "开始之前先看看环境条件，温度和光线对结果的影响比想象中大。",
           "写一份简短的清单并反复使用，既省时间，又不会漏掉枯燥但重要的步骤。", "出了问题时一次只改一个地方，这样才知道是什么起了作用。",
           "每天专注十分钟，比每周一次长时间练习更容易养成习惯。", "请有经验的人看看你的第一次尝试，两分钟的意见可能省下好几个小时。",
           "把工具保持干净并放在固定的位置，听起来很小，却能减少大部分麻烦。", "先做一个简单的版本，等基础熟练后每一轮只加一项改进。",
           "能测量就别靠猜：一把尺子、一个计时器或一个厨房秤就够了。", "第一次的结果不完美很正常，真正的进步在第二次和第三次。"]


def make(lang, n, rnd):
    topics, asks, bits = (EN_TOPICS, EN_ASK, EN_BITS) if lang == "en" else (ZH_TOPICS, ZH_ASK, ZH_BITS)
    out = []
    for i in range(n):
        t = topics[i % len(topics)]
        user = rnd.choice(asks).format(t=t)
        paras = []
        for _ in range(rnd.randint(3, 5)):
            paras.append(" ".join(rnd.sample(bits, rnd.randint(2, 4))) if lang == "en" else "".join(rnd.sample(bits, rnd.randint(2, 4))))
        lead = f"Here are some thoughts on {t}." if lang == "en" else f"关于{t}，有几点建议。"
        out.append({"lang": lang, "user": user, "assistant": lead + "\n\n" + "\n\n".join(paras)})
    return out


def main():
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "prompts", "filler.json")
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 60
    rnd = random.Random(20261115)
    turns = make("en", n, rnd) + make("zh", n, rnd)
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump({"generator": "tools/mkfiller.py (seed 20261115)", "turns": turns}, f, ensure_ascii=False, indent=0)
    print(f"{len(turns)} turns -> {os.path.basename(out)}")


if __name__ == "__main__":
    main()
