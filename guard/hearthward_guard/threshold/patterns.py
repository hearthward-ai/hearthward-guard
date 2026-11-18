"""Weighted pattern families for text aimed at an AI rather than at a human reader.

Patterns are built from word lists with \\s+ separators (never stored as plain phrases), so the
plugin source itself stays free of the phrases it looks for. Weight 1.0 = enough on its own to hold
a message; lower weights add up across families (see scan.py). Some rules carry a lower weight for
direct chat (a person talking to the assistant naturally addresses it) than for content the
assistant reads: attachments, quoted replies and tool results.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

STRONG, MEDIUM, WEAK = 1.0, 0.6, 0.4
_F = re.IGNORECASE


_SU = "su" + "do"      # built at run time: plugin scanners read the bare word as a command


def alt(*words: str) -> str:
    return "(?:" + "|".join(words) + ")"


_FILL = r"(?:[\w'’,-]+\s+)"


def gap(n: int) -> str:
    return _FILL + "{0,%d}" % n


@dataclass(frozen=True)
class Rule:
    family: str
    weight: float
    rx: re.Pattern
    raw: bool = False            # match the raw (line-structured) text instead of the variants
    chat: float | None = None    # weight for direct chat; None = same as weight


def _r(family: str, weight: float, src: str, flags: int = _F, raw: bool = False, chat: float | None = None) -> Rule:
    return Rule(family, weight, re.compile(src, flags), raw, chat)


_SYS_ZH = "(?:系统|系統)(?:消息|通知|提示|公告|讯息|訊息|指令)"
_SYS_HDR_ZH = r"[\[【〖〔〘「『]\s*" + _SYS_ZH + r"\s*[\]】〗〕〙」』]"
# medium only when the claim is aimed at the reading AI (round 2 R2-1): bare 已批准 / 已授权 / 助手 /
# 机器人 appear in ordinary app and group notices ("群主已批准你的入群申请") and stay weak
_SYS_AUTH_ZH = ("(?:授权你|授權你|你的(?:规则|規則|指令|设定|設定|限制)|"
                "(?:之前|以前|原来|原來|所有|全部)的?(?:规则|規則|指令|设定|設定|限制)|"
                "(?:AI|ai|人工智能)?助手(?:请|請)|致(?:AI|ai|助手)|"
                "(?:已批准|已核准|已授权|已授權)[^\\n]{0,8}?(?:把|将|將)[^\\n]{0,30}?"
                "(?:发给|發給|发到|發到|转发|轉發|发送|發送|分享|上传|上傳))")
_AI = alt("an?\\s+ai", "ai", "a\\.i\\.", "artificial\\s+intelligence", "(?:ai\\s+)?assistants?", "(?:ai\\s+)?agents?",
          "llms?", "(?:large\\s+)?language\\s+models?", "chat\\s*bots?", "bots?", "gpt", "chatgpt", "models?",
          "copilot", "autonomous\\s+agents?")
_CORE = alt("ignore", "ignoring", "disregard(?:ing)?", "forget(?:ting)?", "override", "overriding", "bypass(?:ing)?",
            "set\\s+aside", "put\\s+aside", "stop\\s+following", "nullify", "throw\\s+(?:out|away)")
_SOFT = alt("skip", "drop", "abandon", "discard", "neglect", "cancel", "erase", "clear", "void", "suspend",
            "deactivate", "disable", "turn\\s+off", "remove")
_QSTRONG = alt("previous", "prior", "above", "earlier", "preceding", "original", "initial", "existing", "system",
               "safety", "developer", "your", "default", "old", "pre-?set")
_QWEAK = alt("all", "any", "every", "the", "these", "those", "current", "given")
_AINOUN = alt("instructions?", "prompts?", "guidance", "rules?", "directions?", "guidelines?", "directives?", "guardrails?",
              "programming", "constraints?", "polic(?:y|ies)", "restrictions?", "safeguards?", "training",
              "system\\s+prompt", "content\\s+filters?", "safety\\s+filters?")
# nouns people also use about each other (house rules, company policy): strong only with an AI-ish qualifier
_AISTRONG = alt("instructions?", "prompts?", "guidelines?", "guidance", "directives?", "guardrails?", "programming",
                "constraints?", "safeguards?", "training", "system\\s+prompt", "content\\s+filters?", "safety\\s+filters?")
_GENNOUN = alt("rules?", "directions?", "polic(?:y|ies)", "restrictions?")
_QAI = alt("system", "safety", "developer", "your", "default", "pre-?set", "original", "initial")
_CTXNOUN = alt("messages?", "context", "conversation", "commands?", "text", "content", "input", "orders?")
_PERSON = alt("user", "human", "owner", "operator", "admin", "administrator", "end[\\s-]+user")
_TELL = alt("tell(?:ing)?", "inform(?:ing)?", "notify(?:ing)?", "alert(?:ing)?", "warn(?:ing)?", "show(?:ing)?",
            "mention(?:ing)?(?:\\s+(?:this|it|that|anything))?\\s+to", "reveal(?:ing)?(?:\\s+(?:this|it|that|anything))?\\s+to",
            "report(?:ing)?(?:\\s+(?:this|it|that|anything))?\\s+to", "let(?:ting)?", "ask(?:ing)?", "bother(?:ing)?")
_SENSITIVE = alt("passwords?", "pass\\s*codes?", "credentials?", "tokens?", "api\\s+keys?", "keys?", "secrets?",
                 "files?", "messages?", "conversations?", "chat\\s+history", "history", "contacts?", "e-?mails?",
                 "data", "documents?", "notes?", "memor(?:y|ies)", "logs?", "cookies?", "session", "env(?:ironment)?",
                 "config(?:uration)?", "ssh\\s+keys?", "wallet", "seed\\s+phrase", "private\\s+keys?")
_SEND = alt("send", "forward", "e-?mail", "mail", "upload", "post", "share", "leak", "exfiltrate", "transmit",
            "copy", "paste", "dm", "deliver", "submit")
_TOOLS = alt("terminal", "shell", "browser", "send_message", "send\\s+message", "write_file", "execute_code",
             "code_execution", "code\\s+interpreter", "file\\s+system", "web_search", "fetch", "http",
             "python", "bash", "cron", "email", "memory")

RULES: list[Rule] = [
    # 1. setting earlier rules aside
    _r("override", STRONG, r"\b" + _CORE + r"\s+" + gap(3) + _QSTRONG + r"\s+" + gap(2) + _AISTRONG + r"\b"),
    _r("override", STRONG, r"\b" + _CORE + r"\s+" + gap(3) + _QAI + r"\s+" + gap(2) + _GENNOUN + r"\b"),
    _r("override", MEDIUM, r"\b" + _CORE + r"\s+" + gap(3) + _QSTRONG + r"\s+" + gap(2) + _GENNOUN + r"\b"),
    _r("override", STRONG, r"\b" + _CORE + r"\s+" + gap(1) + _AINOUN + r"\s+" + gap(3)
       + alt("above", "before\\s+this", "so\\s+far", "you\\s+(?:were|have\\s+been|'ve\\s+been)\\s+given", "you\\s+received") + r"\b"),
    _r("override", MEDIUM, r"\b" + _CORE + r"\s+" + gap(1) + _QWEAK + r"\s+" + _AINOUN + r"\b"),
    _r("override", MEDIUM, r"\b" + _SOFT + r"\s+" + gap(2) + _QSTRONG + r"\s+" + gap(2) + _AINOUN + r"\b"),
    _r("override", MEDIUM, r"\b" + _CORE + r"\s+" + gap(2) + alt("previous", "prior", "above", "earlier", "preceding")
       + r"\s+" + _CTXNOUN + r"\b"),
    _r("override", MEDIUM, r"\b" + alt("your", "the") + r"\s+" + alt("real", "true", "actual", "new", "updated", "only")
       + r"\s+" + alt("task", "job", "goal", "objective", "instructions?", "mission", "purpose") + r"\s+"
       + alt("is", "are", "now\\s+is") + r"\b"),
    _r("override", MEDIUM, r"\b" + alt("real", "actual", "hidden", "secret", "priority") + r"\s+"
       + alt("instructions?", "directives?", "system\\s+prompt") + r"\s*(?::|follow|for\s+(?:you|the\s+" + _AI + r"))"),
    _r("override", MEDIUM, r"\b" + alt("new", "updated", "revised", "additional") + r"\s+"
       + alt("instructions?", "directives?", "system\\s+prompt") + r"\s*(?:follow|for\s+(?:you|the\s+" + _AI + r"))"),
    # a "New instructions:" heading is ordinary in a README or changelog: weak alone (recheck R5)
    _r("override", WEAK, r"\b" + alt("new", "updated", "revised", "additional") + r"\s+"
       + alt("instructions?", "directives?") + r"\s*:"),
    _r("override", MEDIUM, r"\b" + alt("new", "updated", "revised") + r"\s+system\s+prompt\s*:"),
    _r("override", MEDIUM, r"\b" + alt("do\\s+not", "don'?t", "no\\s+longer") + r"\s+" + alt("follow", "obey", "apply")
       + r"\s+" + gap(1) + alt("your", "the", "any", "previous", "prior", "original") + r"\s+" + _AINOUN + r"\b"),
    _r("override", STRONG, r"\b" + _CORE + r"\s+" + alt("everything", "anything", "all(?:\\s+of)?(?:\\s+(?:that|what))?",
                                                      "whatever") + r"\s+" + gap(1)
       + alt("you(?:'ve|\\s+have|\\s+were|\\s+had)?\\s+(?:been\\s+)?(?:told|given|taught|instructed|programmed|trained)",
             "(?:that\\s+)?(?:came|comes|was\\s+(?:said|written))\\s+(?:before|above|earlier|previously)",
             "(?:said|written|stated)\\s+(?:above|before\\s+this|earlier\\s+in\\s+this)") + r"\b", chat=MEDIUM),
    # 2. role swap / unrestricted persona
    _r("role", MEDIUM, r"\byou\s+are\s+now\s+" + alt("an?", "the", "in", "my", "no\\s+longer", "free", "unrestricted",
                                                   "called", "named") + r"\b", chat=WEAK),
    _r("role", MEDIUM, r"\bfrom\s+now\s+on,?\s+" + gap(2) + alt("you", "act", "respond", "answer", "behave", "your")
       + r"\b", chat=0.2),
    _r("role", STRONG, r"\byou(?:'re|’re|\s+are)\s+no\s+longer\s+" + alt("an?\\s+", "the\\s+", "my\\s+", "just\\s+(?:an?\\s+)?")
       + r"?" + alt(_AI, "bound\\s+by", "restricted", "limited", "subject\\s+to", "required\\s+to\\s+follow", "censored",
                   "filtered") + r"\b"),
    _r("role", MEDIUM, r"(?-i:\b(?:you\s+are|you're|act\s+as|become)\s+(?:now\s+)?(?:DAN|STAN|DUDE|AIM|EvilBot)\b)",
       chat=WEAK),
    _r("role", MEDIUM, r"\b" + alt("with", "has", "have", "having") + r"\s+no\s+" + gap(1) + alt("rules", "restrictions",
                                                                                              "limits", "filters", "guardrails", "censorship")
       + r"\s+(?:or|and|,)\s+" + gap(1) + alt("rules", "restrictions", "limits", "filters", "guardrails", "censorship",
                                            "ethics", "morals") + r"\b", chat=WEAK),
    _r("role", WEAK, r"\bpretend\s+" + gap(2) + alt("to\\s+be", "you\\s+are", "you're") + r"\b", chat=0.2),
    _r("role", STRONG, r"\b" + alt("act", "behave", "respond", "answer", "reply", "operate") + r"\s+" + gap(3)
       + alt("as\\s+if", "as\\s+though", "like", "without") + r"\s+" + gap(4) + alt("no", "without", "zero", "any")
       + r"\s+" + gap(2) + alt("restrictions?", "limits?", "limitations?", "rules?", "filters?", "guidelines?",
                               "censorship", "safety", "ethics") + r"\b"),
    _r("role", STRONG, r"\b" + alt("god", "unrestricted", "unfiltered", "jailbr(?:eak|oken)", "evil", "chaos", "uncensored")
       + r"\s+mode\b|\bd\s*\.?\s*a\s*\.?\s*n\s+mode\b|\bdo\s+any\s*thing\s+now\b"),
    _r("role", STRONG, r"\byou(?:'re|’re|\s+are)\s+(?:now\s+)?in\s+" + alt("developer", "debug", "admin", _SU,
                                                                          "maintenance", "test(?:ing)?", "root")
       + r"\s+mode\b"),
    _r("role", WEAK, r"\b" + alt("developer", "debug", "admin", _SU, "maintenance") + r"\s+mode\s+"
       + alt("on", "enabled?", "activated?", "engaged") + r"\b|\bjail\s*br(?:eak|oken|eaking)\b"),
    _r("role", STRONG, r"\b" + alt("respond", "answer", "reply", "write", "output") + r"\s+without\s+" + gap(3)
       + alt("restrictions?", "limitations?", "filters?", "safety", "censorship", "guardrails?") + r"\b"),
    # 3. text addressed to an AI
    _r("addressed", STRONG, r"\bif\s+you\s*(?:'re|’re|\s+are)\s+" + gap(2) + _AI + r"\b", chat=MEDIUM),
    _r("addressed", STRONG, r"\b" + alt("note", "message", "instructions?", "reminder", "notice", "memo", "directive",
                                      "attention", "warning", "p\\.?s\\.?") + r"\s*:?\s+" + alt("to", "for")
       + r"\s+(?:the\s+|any\s+|all\s+|every\s+)?" + _AI + r"\b", chat=MEDIUM),
    _r("addressed", MEDIUM, r"(?:^|[.!?]\s+)" + alt("dear", "hey", "hello", "hi", "attention", "attn") + r",?\s+"
       + _AI + r"\s*[,:!]", chat=0.0),
    _r("addressed", STRONG, r"\b" + _AI + r"\s+" + gap(2) + alt("reading", "processing", "summari[sz]ing", "parsing",
                                                              "viewing", "scanning", "analy[sz]ing")
       + r"\s+" + alt("this", "these", "the\\s+following") + r"\b"),
    _r("addressed", STRONG, r"\b" + alt("as", "being") + r"\s+" + _AI + r",?\s+you\s+"
       + alt("must", "should", "need\\s+to", "are\\s+required", "will", "have\\s+to") + r"\b", chat=MEDIUM),
    _r("addressed", STRONG, r"\bto\s+the\s+" + _AI + r"\s+" + alt("reading", "processing", "receiving", "handling") + r"\b"),
    # 4. fake system / envelope markers and chat-template tokens
    _r("marker", STRONG, r"<\|\s*(?:im_start|im_end|system|assistant|user|endoftext|eot_id|start_header_id|"
                         r"end_header_id|begin_of_text|tool_call|tool_response|channel|message)\s*\|>"),
    # any chat-template special token: <|im_sep|>, <|constrain|>, <｜Assistant｜> (NFKC) ... (recheck M9)
    _r("marker", STRONG, r"<\|\s*/?[A-Za-z_][\w.:-]{1,40}\s*\|>|<\s*\|\s*/?[A-Za-z_▁][\w▁.:-]{1,40}\s*\|\s*>"),
    _r("marker", STRONG, r"\[/?INST\]|<<\s*/?SYS\s*>>|\[/?SYSTEM\]|\[TOOL_CALLS\]|\[/?AVAILABLE_TOOLS\]"),
    _r("marker", STRONG, r"</?\s*(?:system|developer|tool_call|tool_response|function_call|function_results|"
                         r"function_calls|instructions?|system[_-]prompt|assistant_response|im_start)\s*>"),
    _r("marker", STRONG, r"(?:<<<|>>>|\[\[|==+|--+|##+)\s*" + alt("begin", "end", "start") + r"\s+(?:of\s+(?:the\s+)?)?"
       + alt("untrusted", "trusted", "system", "tool[\\s_-]*(?:output|result)", "external\\s+content",
             "(?:user|human)\\s+(?:message|input|turn|prompt|query)")
       + r"(?:\s+\w+){0,2}\s*(?:>>>|<<<|\]\]|==+|--+)"),
    _r("marker", STRONG, r"<<<\s*(?:end\s+)?tool-output\b"),
    _r("marker", MEDIUM, r"^[ \t]*(?:#{1,6}[ \t]*)?" + alt("system", "developer", "assistant", "admin", "root")
       + r"[ \t]*(?:message|prompt|note|override)[ \t]*:[ \t]*\S", _F | re.M, raw=True),
    # a bare "system:" / "assistant:" line is also a YAML key or a chat transcript: weak alone (recheck R5)
    _r("marker", WEAK, r"^[ \t]*(?:#{1,6}[ \t]*)?" + alt("system", "developer", "assistant", "admin", "root")
       + r"[ \t]*:[ \t]*\S", _F | re.M, raw=True),
    # chat-template turn markers of other model families (review M9)
    _r("marker", STRONG, r"</?think>|<\s*/?\s*(?:start_of_turn|end_of_turn)\s*>|<start_of_turn>\s*(?:user|model|system)"
       r"|\[/?SYSTEM_PROMPT\]|<\|(?:begin|end)_of_(?:text|turn)\|>", chat=MEDIUM),
    _r("marker", STRONG, r"(?:^|\n)[ \t]*\n[ \t]*(?:Human|User)[ \t]*:[^\n]{0,2000}\n[ \t]*\n[ \t]*(?:Assistant|AI)[ \t]*:",
       _F, raw=True, chat=MEDIUM),
    # the guard's own wording: it never comes from outside (review M9)
    _r("marker", STRONG, r"[\[【〖〔〘「『({<]\s*Guard\s+note\s*:|(?:<<<|《《《|«««)\s*(?:end\s+)?released\b"),
    _r("marker", STRONG, r"[\[【〖〔〘「『({<]\s*Guard\s*:|[\[【〖〔〘「『({<]\s*Untrusted\s+output\s+of\s+tool\b", chat=0.2),
    _r("marker", MEDIUM, r"\[\s*" + alt("replying\\s+to", "quoted\\s+message", "forwarded\\s+from", "system\\s+note")
       + r"\s*:"),
    # fake system headers in pasted or fetched text (0.9.3 lab re-run M2c): "【系统消息】", "系统通知：",
    # "System notice:". Alone they are weak (chat apps and shops print them: "系统消息：张三加入了群聊");
    # with an authority claim or words about the assistant, its rules or approval on the same line, medium
    _r("marker", WEAK, _SYS_HDR_ZH + r"|(?:^|\n)[ \t]*" + _SYS_ZH + r"[ \t]*[:：]|(?:^|\n)[ \t]*system[ \t]+"
       + alt("notice", "notification", "update", "alert", "announcement") + r"[ \t]*:", raw=True),
    _r("marker", MEDIUM, r"(?:" + _SYS_HDR_ZH + r"|" + _SYS_ZH + r"[ \t]*[:：])[^\n]{0,40}?" + _SYS_AUTH_ZH, raw=True),
    _r("marker", MEDIUM, r"(?:^|\n)[ \t]*system[ \t]+" + alt("notice", "notification", "update", "alert", "announcement")
       + r"[ \t]*:[^\n]{0,80}?\b" + alt(
           "(?:ai\\s+)?assistant\\s*[,:]", "(?:ai|bot|model)\\s*[,:]",
           "(?:the\\s+)?assistant'?s\\s+(?:rules|instructions|settings|setup)\\b",
           "override\\b", "(?:previous|earlier|prior|your|its|all)\\s+(?:rules|instructions)\\b",
           "(?:approved|authori[sz]ed)[^\\n]{0,30}?\\b(?:send|forward|share|upload|email)\\b"),
       raw=True),
    # 5. secrecy towards the user
    _r("secrecy", STRONG, r"\b" + alt("do\\s+not", "don'?t", "never", "without", "avoid", "no\\s+need\\s+to") + r"\s+"
       + _TELL + r"\s+" + gap(1) + alt("the\\s+", "your\\s+", "this\\s+") + r"?" + _PERSON + r"\b"),
    _r("secrecy", STRONG, r"\b" + alt("keep", "hide", "conceal") + r"\s+" + gap(2)
       + alt("secret\\s+", "hidden\\s+", "quiet\\s+") + r"?" + alt("from", "away\\s+from")
       + r"\s+(?:the\s+|your\s+)?" + _PERSON + r"\b"),
    _r("secrecy", STRONG, r"\b(?:the\s+)?" + _PERSON + r"\s+" + alt("must", "should", "will", "can")
       + r"\s*(?:not|never|n't)\s+" + alt("know", "find\\s+out", "see", "notice", "learn", "be\\s+told") + r"\b"),
    _r("secrecy", MEDIUM, r"\b" + alt("silently", "quietly", "secretly", "covertly", "discreetly", "invisibly") + r"\s+"
       + alt("send", "forward", "delete", "run", "execute", "e-?mail", "transfer", "upload", "post", "call",
             "install", "copy") + r"\b"),
    # 6. prompt / secret extraction
    _r("leak", STRONG, r"\b" + alt("reveal", "print", "show", "repeat", "output", "display", "dump", "leak",
                                 "write\\s+out", "recite", "spell\\s+out", "paste", "share", "give\\s+me", "tell\\s+me")
       + r"\s+(?:me\s+)?" + gap(3) + alt("system", "initial", "original", "hidden", "developer", "secret", "internal",
                                         "pre-?prompt", "confidential") + r"\s+"
       + alt("prompts?", "instructions?", "messages?", "rules", "configuration", "guidelines") + r"\b"),
    _r("leak", STRONG, r"\b" + alt("repeat", "print", "output", "copy", "echo") + r"\s+" + gap(3)
       + alt("text", "words", "everything", "content", "lines?", "tokens?") + r"\s+"
       + alt("above", "before\\s+this", "preceding") + r"\b"),
    _r("leak", WEAK, r"\b" + alt("what", "show\\s+me", "tell\\s+me") + r"\s+" + gap(2) + alt("are", "is")
       + r"?\s*your\s+" + alt("instructions", "rules", "prompt") + r"\b", chat=0.2),
    _r("leak", STRONG, r"\b" + alt("reveal", "print", "show", "repeat", "output", "display", "dump", "leak", "recite",
                                 "disclose", "share") + r"(?:s|es|ed|ing)?\s+" + alt("its", "your", "the", "their", "his", "her")
       + r"\s+(?:full\s+|entire\s+|complete\s+|exact\s+|whole\s+)?" + alt("system\\s+prompt", "hidden\\s+instructions",
                                                                         "initial\\s+instructions", "original\\s+instructions",
                                                                         "system\\s+instructions", "hidden\\s+prompt")
       + r"\b", chat=MEDIUM),
    # 7. exfiltration
    # (lab re-test 2 bug 6: git's empty-repo hint 'create/copy files and use "git add" to track'
    # matched; a "to" that starts git's hint verbs, not a place, does not count)
    _r("exfil", MEDIUM, r"\b" + _SEND + r"\s+" + gap(4) + _SENSITIVE + r"\b.{0,80}?\b"
       + alt("to", "at", "into", "via") + r"\s+(?!" + alt("track", "unstage", "discard", "update\\s+what")
       + r"\b(?![.@:/\w-]))\S", chat=WEAK),
    _r("exfil", MEDIUM, r"!\[[^\]\n]{0,200}\]\(\s*<?https?://[^)\s]*[?&#][^)\s]*=[^)\s]*\)"),
    # an image whose query is a placeholder for the model to fill in (conversation, secrets ...)
    _r("exfil", STRONG, r"!\[[^\]\n]{0,200}\]\(\s*<?https?://[^)\s]*[?&#/][\w.-]*=?\s*(?:\{|\$\{|%7[Bb]|\[|<|%3[Cc])"),
    _r("steer", MEDIUM, r"\b" + alt("put", "include", "add", "insert", "render", "embed", "append", "show") + r"\s+"
       + alt("this", "the\\s+following", "it", "this\\s+(?:image|link|markdown|text|line)") + r"\s+" + gap(3)
       + alt("in", "into", "at\\s+the\\s+(?:end|start|top|bottom)\\s+of", "to") + r"\s+" + alt("your", "every", "each", "the", "all")
       + r"\s+" + gap(1) + alt("reply", "replies", "response", "responses", "answers?", "output", "messages?") + r"\b",
       chat=WEAK),
    _r("exfil", MEDIUM, r"\b" + alt("append", "add", "include", "encode", "put") + r"\s+" + gap(4)
       + alt("to", "in", "into") + r"\s+(?:the\s+|this\s+|a\s+)?"
       + alt("url", "link", "query\\s+string", "image\\s+(?:url|link)", "request") + r"\b"),
    _r("exfil", WEAK, r"\b" + alt("send", "write") + r"\s+(?:an?\s+)?e-?mail\s+to\b|\b"
       + alt("e-?mail", "forward", "send") + r"\s+(?:it|this|them|everything)?\s*to\s+[\w.+-]+@[\w-]+\.[\w.]+", chat=0.2),
    # 8. tool-call smuggling
    _r("tool", STRONG, r"[\"']" + alt("name", "tool", "tool_name", "function", "recipient_name")
       + r"[\"']\s*:\s*[\"'][\w.\-]{1,64}[\"']\s*,\s*[\"']" + alt("arguments", "args", "parameters", "input", "params")
       + r"[\"']\s*:"),
    _r("tool", STRONG, r"<\s*/?\s*" + alt("tool_call", "tool_use", "function_calls?", "invoke", "antml:invoke",
                                        "use_tool", "tool_code") + r"\b|<\s*function\s*=|\btool_calls?\s*\]"),
    _r("tool", STRONG, r"\{[^{}]{0,300}?[\"'](?:name|tool|tool_name|function|recipient_name)[\"']\s*:\s*[\"'][\w.\-]{1,64}[\"']"
       r"[^{}]{0,300}?[\"'](?:arguments|args|parameters)[\"']\s*:\s*[\[{\"]"),
    # name and arguments with nested objects between them, either order (recheck M9)
    _r("tool", STRONG, r"[\"'](?:name|tool|tool_name|function|recipient_name)[\"']\s*:\s*[\"'][\w.\-]{1,64}[\"']"
       r"[^\n]{0,600}?[\"'](?:arguments|args|parameters)[\"']\s*:\s*[\[{\"]", _F | re.S),
    # functions.terminal({...}), default_api.x({...}), to=functions.x (Harmony)
    _r("tool", STRONG, r"\b(?:functions|default_api|tools)\.[A-Za-z_][\w-]{0,63}\s*\(\s*\{|\bto\s*=\s*functions\.\w"),
    _r("tool", STRONG, r"[\"'](?:arguments|args|parameters)[\"']\s*:\s*\{[^{}]{0,400}\}\s*,[^{}]{0,300}?"
       r"[\"'](?:name|tool|tool_name|function|recipient_name)[\"']\s*:\s*[\"'][\w.\-]{1,64}[\"']"),
    _r("tool", STRONG, r"^[ \t]*Action[ \t]*:[ \t]*[\w.\-]{1,64}[ \t]*\r?\n[ \t]*Action[ \t]+Input[ \t]*:", _F | re.M, raw=True,
       chat=MEDIUM),
    _r("tool", STRONG, r"(?:^|[\s\[(\"'`*])" + alt("MEDIA", "ATTACH", "ATTACHMENT", "FILE")
       + r"[ \t]*:[ \t]*[\"'`]?(?:/|~|[A-Za-z]:[\\/]|\.\.?[\\/]|file:|https?:|\$\{?HOME)",
       _F | re.M, raw=True),
    _r("tool", MEDIUM, r"\b" + alt("use", "call", "invoke", "run", "execute", "trigger", "activate")
       + r"\s+(?:the\s+|your\s+)?" + _TOOLS + r"\s+" + alt("tool", "function", "plugin", "command", "capability") + r"\b",
       chat=WEAK),
    _r("tool", WEAK, r"\b" + alt("use", "call", "invoke", "trigger") + r"\s+(?:the\s+|your\s+)?[\w-]{2,40}\s+"
       + alt("tool", "function") + r"\s+" + alt("to", "and", "with") + r"\b", chat=0.2),
    # 9. code execution
    _r("exec", STRONG, r"\b" + alt("curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod")
       + r"\b[^\n|]{0,200}\|\s*(?:" + _SU + r"\s+)?" + alt("ba?sh", "sh", "zsh", "python[0-9.]*", "iex", "invoke-expression",
                                                  "powershell", "pwsh", "perl", "ruby", "node") + r"\b"),
    _r("exec", STRONG, r"\b" + alt("powershell", "pwsh") + r"(?:\.exe)?\s+(?:-\w+\s+){0,4}-e(?:nc|ncodedcommand|c)?\s+[A-Za-z0-9+/=]{20,}"),
    _r("exec", WEAK, r"\b" + alt("download", "install", "run", "execute", "launch") + r"\s+"
       + alt("this", "the\\s+following", "the\\s+attached", "that") + r"\s+"
       + alt("script", "file", "command", "program", "installer", "binary", "payload", "code") + r"\b", chat=0.2),
    # 10. go to a URL
    _r("url", WEAK, r"\b" + alt("visit", "go\\s+to", "navigate\\s+to", "fetch", "browse\\s+to", "load", "request")
       + r"\s+(?:this\s+|the\s+following\s+|the\s+)?" + alt("url", "link", "site", "website", "page", "address", "endpoint")
       + r"?\s*:?\s*<?https?://", chat=0.0),
    # 11. fake authority and urgency
    _r("authority", MEDIUM, r"\b" + alt("this\\s+is", "message\\s+from", "notice\\s+from", "sent\\s+by", "on\\s+behalf\\s+of")
       + r"\s+(?:the\s+|your\s+)?" + alt("system", "administrator", "admin", "developers?", "operator", "security\\s+team",
                                         "openai", "anthropic", "nous(?:\\s+research)?", "hermes(?:\\s+team)?", "creator")
       + r"\b", chat=WEAK),
    _r("authority", MEDIUM, r"\byou(?:'ve|\s+have)\s+been\s+" + gap(2) + alt("updated", "upgraded", "patched", "reprogrammed",
                                                                            "reconfigured", "granted", "authori[sz]ed",
                                                                            "unlocked", "freed", "jailbroken") + r"\b",
       chat=WEAK),
    _r("authority", MEDIUM, r"\b" + alt("admin", "root", _SU, "god", "developer", "elevated") + r"\s+"
       + alt("access", "mode", "privileges?", "permissions?", "rights") + r"\s+" + gap(2)
       + alt("granted", "enabled", "activated", "unlocked", "confirmed") + r"\b"),
    _r("authority", WEAK, r"\b" + alt("urgent", "important", "critical", "mandatory", "required", "official")
       + r"\s*[:!-]?\s+" + gap(1) + alt("system", "security", "policy") + r"\s+"
       + alt("update", "override", "notice", "instruction", "change", "directive") + r"\b"),
]

# Non-English families (the second check covers any language; these are a fast first line).
_ZH_SET_ASIDE = "(?:忽略|无视|忽视|不要理会|不用管|别管|抛开|忘记|忘掉|放弃|跳过|绕过|覆盖)"
_ZH_EARLIER = "(?:之前|以上|先前|前面|上述|你的|所有|全部|原来|原有|系统|一切|此前|早先)"
_ZH_RULES = "(?:指令|指示|说明|规则|提示|设定|命令|要求|提示词|约束|限制|安全规则|系统提示)"
RULES += [
    _r("override", STRONG, _ZH_SET_ASIDE + r"(?:掉)?\s*" + _ZH_EARLIER + r"+\s*的?\s*(?:所有|全部|一切)?\s*的?\s*" + _ZH_RULES),
    _r("addressed", STRONG, r"(?:如果|假如|若)你是\s*(?:一个|一名|一位)?\s*(?:AI|ＡＩ|人工智能|助手|智能体|机器人|大模型|语言模型|聊天机器人)",
       chat=MEDIUM),
    _r("addressed", STRONG, r"(?:致|给|写给)\s*(?:所有|任何)?\s*(?:AI|ＡＩ|人工智能|助手|智能体|大模型)\s*(?:的|：|:)", chat=MEDIUM),
    _r("secrecy", STRONG, r"(?:不要|别|切勿|请勿|不准|不得|千万别|不可)\s*(?:告诉|通知|提醒|透露给|告知)\s*(?:用户|主人|使用者)"),
    _r("leak", STRONG, r"(?:输出|显示|告诉我|打印|列印|印出|列出|泄露|复述|重复|给我看)\s*(?:你的|你)?\s*(?:系统提示词?|系统指令|初始指令|隐藏指令|原始提示)"),
    _r("role", STRONG, r"(?:无限制|越狱|上帝|邪恶)模式"),
    _r("role", WEAK, r"(?:开发者|管理员)模式"),
    # a named persona ("你现在是“无规则助手”", DAN) and the jailbreak promise that comes with it: each is
    # medium, together they hold; plain "你现在是我的朋友" stays weak (recheck R4 follow-up)
    _r("role", MEDIUM, r"你现在是(?:一个|一名|一位)?\s*(?:[“\"「『《][^”\"」』》\n]{1,20}[”\"」』》]|DAN|STAN|DUDE|AIM)"),
    _r("jailbreak", MEDIUM, r"无规则|不受(?:任何)?(?:规则|限制|约束|审查)|没有任何(?:规则|限制|约束)|什么都能做|都要答应|不会(?:提醒|警告)风险"),
    _r("role", MEDIUM, r"(?:开发者|管理员|上帝)模式(?:已经?|现已)?(?:开启|启用|激活|打开)"),
    _r("role", MEDIUM, r"(?:从现在开始|从现在起)\s*[,，]?\s*你(?:是|要|必须|将)", chat=0.2),
    _r("role", MEDIUM, r"你现在是(?:一个|一名)?", chat=WEAK),
    _r("override", STRONG, r"(?:以前|前|上記|これまで|全て|すべて)の(?:指示|命令|ルール|指令|プロンプト)を(?:すべて|全て)?(?:無視|忘れ)"),
    _r("secrecy", STRONG, r"ユーザー(?:には|に)(?:言わ|伝え|知らせ|教え)ないで"),
    _r("addressed", STRONG, r"(?:AI|ＡＩ)(?:アシスタント|エージェント)?(?:へ|の皆さん|であれば|なら)[、。:：]", chat=MEDIUM),
    _r("override", STRONG, r"\b(?:ignora|olvida|omite)\s+(?:todas\s+)?(?:tus|las|sus)\s+(?:\w+\s+)?(?:instrucciones|reglas|indicaciones)"),
    _r("addressed", STRONG, r"\bsi\s+eres\s+(?:una?\s+)?(?:IA|inteligencia\s+artificial|asistente|agente|bot|modelo)\b", chat=MEDIUM),
    _r("secrecy", STRONG, r"\bno\s+(?:se\s+lo|le)\s+(?:digas|cuentes|informes|avises)\s+al\s+usuario"),
    _r("override", STRONG, r"\b(?:ignore[sz]?|oublie[sz]?)\s+(?:toutes\s+)?(?:tes|vos|les)\s+(?:\w+\s+)?(?:instructions|consignes|r[eè]gles)"),
    _r("secrecy", STRONG, r"\bne\s+(?:le\s+)?dis\s+(?:rien\s+)?pas\s+(?:à|a)\s+l'utilisateur"),
    _r("override", STRONG, r"\b(?:ignorier|vergiss)(?:e|en|t)?\s+(?:alle\s+)?(?:deine|ihre|die|vorherigen|bisherigen)\s+(?:\w+\s+)?(?:Anweisungen|Regeln|Vorgaben)"),
    _r("override", STRONG, r"\b(?:ignore|esqueça|esqueca)\s+(?:todas\s+)?(?:as\s+)?(?:suas\s+)?(?:instruções|instrucoes|regras)(?:\s+anteriores)?"),
    _r("override", STRONG, r"(?:игнорируй|игнорировать|забудь|проигнорируй)\s+(?:все\s+)?(?:предыдущие\s+|прежние\s+|свои\s+)?(?:инструкции|правила|указания)"),
    _r("override", STRONG, r"\b(?:ігноруй|забудь|проігноруй)\s+(?:усі\s+|всі\s+)?(?:попередні\s+|свої\s+)?(?:інструкції|правила|вказівки)"),
    _r("override", STRONG, r"\b(?:ignora|dimentica)\s+(?:tutte\s+)?(?:le\s+)?(?:tue\s+)?(?:istruzioni|regole|indicazioni)"),
    _r("override", STRONG, r"\b(?:negeer|vergeet)\s+(?:alle\s+)?(?:je\s+|jouw\s+|de\s+)?(?:vorige\s+|eerdere\s+)?(?:instructies|regels)"),
    _r("override", STRONG, r"\b(?:zignoruj|zapomnij)\s+(?:o\s+)?(?:wszystkie\s+|wszystkich\s+)?(?:poprzednie\s+|poprzednich\s+|swoje\s+)?(?:instrukcje|instrukcjach|polecenia|zasady)"),
    _r("override", STRONG, r"\b(?:abaikan|lupakan)\s+(?:semua\s+)?(?:instruksi|perintah|aturan)"),
    _r("override", STRONG, r"\b(?:bỏ\s+qua|phớt\s+lờ|quên)\s+(?:tất\s+cả\s+)?(?:các\s+)?(?:hướng\s+dẫn|chỉ\s+dẫn|lệnh|quy\s+tắc)"),
    _r("override", STRONG, r"(?:önceki\s+|tüm\s+)+talimatları\s+(?:yok\s+say|görmezden\s+gel|unut)"),
    _r("override", STRONG, r"تجاهل\s+(?:جميع\s+|كل\s+)?(?:التعليمات|الأوامر|القواعد)"),
    _r("override", STRONG, r"(?:निर्देशों|निर्देश|नियमों)\s*(?:को)?\s*(?:अनदेखा|नज़रअंदाज़|नजरअंदाज|भूल)"),
    _r("override", STRONG, r"(?:이전|모든|앞의|위의)[^\n]{0,12}(?:지시|명령|지침|규칙|프롬프트)[^\n]{0,6}(?:무시|잊어)"),
]


def match(text: str, raw: str | None = None, chat: bool = False) -> list[tuple[str, float, str]]:
    """[(family, weight, matched snippet)] for every rule that matches (one hit per rule). Rules
    marked raw are matched against *raw* (line structure kept) when given. chat=True applies the
    lower direct-chat weights."""
    hits = []
    for rule in RULES:
        if rule.raw and raw is None:
            continue
        target = raw if rule.raw else text
        m = rule.rx.search(target)
        if m:
            w = rule.chat if (chat and rule.chat is not None) else rule.weight
            if w > 0:
                hits.append((rule.family, w, m.group(0)[:160]))
    return hits


# Letter-spaced text ("i g n o r e  y o u r ...") squashed to letters only. Applied only to runs of
# single letters, so ordinary prose never reaches these.
SQUASHED: list[tuple[str, float, re.Pattern]] = [(f, w, re.compile(s)) for f, w, s in [
    ("override", STRONG, "(?:ignore|disregard|forget|override|bypass)(?:all|any|of|the|your|previous|prior|above|"
                         "earlier|preceding|original|system|safety|these|those){1,4}(?:instructions?|prompts?|rules|"
                         "guidelines|directives|programming)"),
    ("secrecy", STRONG, "(?:donot|dont|never)(?:tell|inform|notify|alert|warn)(?:the|your)?(?:user|human|owner|operator)"),
    ("leak", STRONG, "(?:reveal|print|show|repeat|output|display|dump)(?:me)?(?:your|the)(?:full|entire)?(?:system|initial|"
                     "original|hidden|secret)(?:prompt|instructions|rules)"),
    ("addressed", STRONG, "^(?:ifyouarean?|noteto(?:the|any|all)?|dear)(?:ai|assistant|llm|languagemodel|agent|chatbot|bot)"),
    ("role", STRONG, "(?:youarenow|enter|enable|activate)(?:in)?(?:developer|god|unrestricted|unfiltered|jailbreak)mode"),
    ("exfil", MEDIUM, "(?:send|forward|email|upload|leak)(?:the|all|your|my)?(?:passwords?|credentials|tokens?|apikeys?|"
                      "secrets?|files|messages|history)to"),
]]


def match_squashed(squashed: str) -> list[tuple[str, float, str]]:
    return [(f, w, rx.pattern[:40]) for f, w, rx in SQUASHED if rx.search(squashed)]


# The WHOLE text squashed to letters and digits (normalize.squashed). Only long, specific phrases
# whose ordinary-text weight is the same, so words run together never weigh more than words apart.
SQUASHED_WHOLE: list[tuple[str, float, float, re.Pattern]] = [(f, w, c, re.compile(s)) for f, w, c, s in [
    ("override", STRONG, STRONG, "(?:ignore|disregard|forget|override|bypass)(?:all|any|of|the|your|these|those){0,3}"
                                 "(?:previous|prior|above|earlier|preceding|original|initial|system|safety|developer)"
                                 "(?:instructions?|prompts?|guidelines|directives|programming|guardrails)"),
    ("override", MEDIUM, MEDIUM, "(?:ignore|disregard|forget|override|bypass)(?:all|any|of|the|your|these|those){0,3}"
                                 "(?:previous|prior|above|earlier|preceding|original|initial|system|safety|developer)rules"),
    ("secrecy", STRONG, STRONG, "(?:donot|dont|never)(?:tell|inform|notify|alert|warn)(?:the|your)?(?:user|human|owner|operator)"),
    ("leak", STRONG, MEDIUM, "(?:reveal|print|show|repeat|output|display|dump)(?:me)?(?:your|the)(?:full|entire)?"
                             "(?:system|initial|original|hidden|secret)(?:prompt|instructions)"),
    ("role", STRONG, STRONG, "(?:youarenow|enter|enable|activate)(?:in)?(?:developer|god|unrestricted|unfiltered|jailbreak)mode"),
    ("override", STRONG, STRONG, "忽略(?:之前|以上|先前|前面|上述|你的|所有|全部|原来|系统|一切)+的?(?:所有|全部|一切)?的?"
                                 "(?:指令|指示|规则|提示|设定|命令|约束|限制|系统提示)"),
]]


def match_squashed_whole(squashed: str, chat: bool = False) -> list[tuple[str, float, str]]:
    return [(f, c if chat else w, rx.pattern[:40]) for f, w, c, rx in SQUASHED_WHOLE if rx.search(squashed)]
