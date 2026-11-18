"""Scam signs in text people are shown (picture text, job 6): what the sender wants and how they push.

This is not the injection check (that is scan.py). It looks for ordinary scams aimed at a person:
  ASKS        money transfers, gift cards, codes / passwords / ID numbers, crypto, "click to verify",
              "call / add / write to", remote-access apps;
  LURES       urgency and threats, secrecy, impersonation (police, tax office, bank, parcel service ...),
              prizes, refunds and loan approvals, guaranteed returns, paid "tasks", miracle cures;
  INDICATORS  links (shorteners, raw IPs, punycode, look-alike brand domains, risky endings), phone
              numbers, e-mail addresses, crypto wallet addresses, amounts.
assess(text) -> Assessment(level, categories, indicators). Levels: none < low < medium < high.
The reasons people see come from fixed label tables in common/messages.py, never from a model.
Standard library only. English and Chinese phrases (generic: no names, brands of real people or
family details).
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import urlsplit

LEVELS = ("none", "low", "medium", "high")
ASKS = ("ask_money", "ask_giftcard", "ask_secret", "ask_crypto", "ask_click", "ask_contact", "ask_remote")
LURES = ("pressure", "secrecy", "impersonation", "windfall", "investment", "task", "health")
SIGNS = ("crypto_address", "suspicious_link")
ORDER = ASKS + LURES + SIGNS
MAX_CHARS = 20_000
_I = re.IGNORECASE

_EN = {
    "ask_money": [
        # payment redirection: money sent where it should not go. Ordinary billing words ("amount due",
        # "pay now", "pay the balance") are weak asks below (fix round OC-2).
        r"\b(?:wire|transfer|send|deposit|move|zelle|venmo|remit)\b[^.!?\n]{0,40}(?:\b(?:money|funds|cash|payment|"
        r"fee|fine|amount|dollars|usd|balance)\b|\$\s?\d)",
        r"\bpay\b[^.!?\n]{0,20}\b(?:bail|bond)s?\b",
        r"\b(?:processing|release|redelivery|customs|unlock|handling|clearance|activation|insurance) "
        r"(?:fee|charge)s?\b",
        r"\b(?:western union|moneygram)\b", r"\bbail money\b",
        r"\b(?:start|begin|invest|deposit|top up) with \$\s?\d",
    ],
    "ask_money#safe": [r"\bsafe account\b"],          # "move it to a safe account": a scam on its own
    "ask_giftcard": [r"\b(?:buy|purchase|get|send|scratch)\b[^.!?\n]{0,40}\bgift ?cards?\b",
                     r"\b(?:itunes|google play|steam|apple|amazon|target|walmart) (?:gift )?cards?\b",
                     r"\bcard numbers? (?:on|from) the back\b", r"\bpay (?:in|with) gift ?cards?\b"],
    "ask_secret": [
        r"\b(?:give|send|tell|share|read|provide|forward|enter|confirm|reply with)\b[^.!?\n]{0,30}\b(?:verification|"
        r"security|one[- ]time|otp|2fa|login|access|confirmation) (?:code|pin|number)s?",
        r"\b(?:give|send|tell|share|provide|confirm|enter|update|reply with)\b[^.!?\n]{0,30}\b(?:password|passcode|pin|"
        r"social security|ssn|bank account|account number|routing number|card number|cvv|date of birth|"
        r"mother'?s maiden name|seed phrase|recovery phrase|private key)s?\b",
        r"\bwhat(?:'s| is) (?:the|your) (?:code|password|pin)\b", r"\bseed phrase\b|\brecovery phrase\b",
    ],
    "ask_crypto": [r"\b(?:buy|send|transfer|deposit|convert)\b[^.!?\n]{0,30}\b(?:bitcoin|btc|crypto(?:currency)?|"
                   r"usdt|tether|ethereum|eth)\b", r"\b(?:bitcoin|crypto) atm\b", r"\bwallet address\b"],
    "ask_click": [r"\b(?:click|tap|open|visit|follow)\b[^.!?\n]{0,25}\blink\b",
                  r"\bjoin\b[^.!?\n]{0,20}\b(?:vip|group|channel|chat)\b"],
    # "#verify": asks to log in or confirm account details (credential phishing); same reason label
    "ask_click#verify": [r"\b(?:verify|confirm|validate|unlock|reactivate|update|restore)\b[^.!?\n]{0,15}\b(?:your )?"
                         r"(?:account|identity|information|details|payment|address|login)\b",
                         r"\blog ?in (?:here|now|to (?:verify|confirm))\b", r"\bverify (?:login|now|here)\b",
                         r"\b(?:verify|confirm|update)\s*(?:账户|账号|身份|信息|地址)"],
    "ask_contact": [r"\b(?:call|phone|ring|text|whatsapp|message|contact)\b[^.!?\n]{0,25}\b(?:us|me|this number|"
                    r"the number|immediately|now|back|our (?:agent|officer|hotline|support|desk))\b",
                    r"\badd me on\b", r"\breply (?:with|yes|y)\b",
                    r"\b(?:call|phone|text|whatsapp)\b[^.!?\n\d]{0,25}\+?\(?\d{3}", r"\bpress (?:1|one|\d)\b",
                    r"\bsend (?:it|them|the [a-z ]{1,20}) to [^\s@]+@[^\s@]+\.[a-z]{2,}"],
    "ask_remote": [r"\b(?:anydesk|teamviewer|rustdesk|ultraviewer|quick ?support|logmein|supremo)\b",
                   r"\bremote (?:access|control|desktop|support)\b", r"\bshare your screen\b",
                   r"\b(?:download|install)\b[^.!?\n]{0,25}\b(?:app|software|program|tool)\b[^.!?\n]{0,25}\b(?:support|"
                   r"help|fix|secure|protect|remove|clean)"],
    "pressure": [r"\burgent(?:ly)?\b", r"\bwithin (?:\d{1,2}|24|48|72) (?:hours|hrs)\b",
                 r"\bfinal warning\b",
                 r"\b(?:account|card|social security number|computer|device|pc)\b[^.!?\n]{0,20}\b(?:suspended|locked|"
                 r"frozen|blocked|compromised|closed|deactivated|infected|hacked)\b",
                 r"\b(?:arrest(?:ed)?|warrant|lawsuit|legal action|deport(?:ed|ation)?)\b",
                 r"\bact (?:now|fast)\b", r"\bin jail\b", r"\b(?:been|got) arrested\b",
                 r"\bavoid (?:arrest|suspension)\b",
                 r"\b(?:virus|malware|trojan)\b[^.!?\n]{0,20}\b(?:detected|found)\b",
                 r"\b(?:cannot|can't|could not|unable to) (?:be )?deliver"],
    "secrecy": [r"\bdon'?t tell (?:anyone|anybody|your|the bank|family|mom|dad|mum|grandma|grandpa|"
                r"my (?:parents|mom|dad)|them|him|her)\b", r"\bkeep (?:this|it) (?:a )?(?:secret|"
                r"confidential|between us)\b", r"\bdo not (?:tell|inform|discuss)\b"],
    "impersonation": [r"\b(?:this is|i am|i'm|we are|calling from|from the|on behalf of)\b[^.!?\n]{0,15}\b(?:irs|"
                      r"ssa|social security(?: administration)?|fbi|dea|police|sheriff|medicare|customs|border patrol|"
                      r"immigration|embassy|consulate|bank|amazon|apple|microsoft|paypal|fedex|ups|usps|dhl|"
                      r"tech support|support team|your (?:grandson|granddaughter|son|daughter|nephew))\b",
                      r"\b(?:irs|ssa|fbi|usps) (?:agent|officer|notice|department)\b",
                      r"\b(?:grandpa|grandma|grandfather|grandmother|dad|mom|uncle|aunt),? (?:it'?s|this is) me\b",
                      r"\b(?:microsoft|apple|windows) (?:support|security|technician)\b",
                      r"\b(?:police|court|tax office|immigration) (?:notice|officer|department)\b"],
    "windfall": [r"\byou(?:'ve| have)? (?:won|been selected)\b", r"\b(?:lottery|sweepstakes|jackpot|inheritance)\b",
                 r"\b(?:claim|receive|collect) (?:your|the)\b[^.!?\n]{0,15}\b(?:prize|reward|refund|payment|package|"
                 r"winnings)\b", r"\boverpa(?:id|yment)\b", r"\bunclaimed (?:funds|money|package)\b",
                 r"\brefund (?:of|for) \$?\d", r"\bcongratulations\b[^.!?\n]{0,30}\b(?:won|winner|selected|prize)",
                 r"\b(?:pre-?approv(?:ed|al)|loan approved|\$[\d,]+(?:\.\d+)? (?:is )?approved)\b",
                 r"\brefund\b\s?(?:失败|failed|pending|on hold|could not)"],
    "investment": [r"\bguaranteed (?:returns?|profits?|income)\b", r"\brisk[- ]free\b", r"\bdouble your money\b",
                   r"\b\d{1,4}(?:\.\d+)?\s?% (?:returns?|profit|monthly|weekly|daily|a day|per day|interest)\b",
                   r"\binsider (?:tip|information)\b", r"\btrading (?:group|signals|mentor|app|platform)\b",
                   r"\bvip (?:group|signals|channel)\b"],
    "health": [r"\bmiracle\b[^.!?\n]{0,20}\b(?:cure|pill|supplement|remedy|treatment)s?\b",
               r"\bcures?\b[^.!?\n]{0,20}\b(?:arthritis|diabetes|cancer|dementia|pain|disease)\b",
               r"\b(?:no more|reverse[sd]?)\b[^.!?\n]{0,15}\b(?:diabetes|arthritis|dementia)\b"],
    "task": [r"\b(?:like|rate|review)\b[^.!?\n]{0,20}\b(?:videos?|products?|posts?)\b[^.!?\n]{0,30}\b(?:earn|paid|\$)",
             r"\bearn \$?\d[\d,]*\s?(?:a|per) (?:day|hour)\b", r"\b(?:recharge|top up) (?:to )?(?:unlock|continue)\b",
             r"\bcommission\b[^.!?\n]{0,30}\b(?:task|order)s?\b"],
}
_ZH = {
    "ask_money": ["转账", "汇款", "打款", "打钱", "汇钱", "转钱", "保证金", "手续费", "解冻费",
                  "保释金", "垫付", "收款码", "验证流水", "刷流水", "先充"],
    "ask_money#safe": ["安全账户", "安全帐户", "监管账户"],
    "ask_giftcard": ["卡密"],
    "ask_crypto": ["比特币", "泰达币", "USDT", "虚拟货币", "加密货币", "数字货币", "钱包地址"],
    "ask_click": ["点击链接", "点链接", "打开链接", "点击下方"],
    "ask_click#verify": ["登录验证", "验证账户", "验证身份", "身份验证", "账户验证", "链接登录", "更新地址"],
    "ask_contact": ["加我微信", "加微信", "加QQ", "回电", "拨打", "致电", "联系客服", "联系专员", "添加客服", "私聊",
                    "加助理", "加老师", "进群", "入群", "加群", "转接"],
    "ask_remote": ["远程控制", "远程协助", "屏幕共享", "共享屏幕", "下载APP", "下载app", "安装软件"],
    "pressure": ["紧急", "24小时内", "冻结", "逮捕", "通缉", "起诉", "涉嫌", "涉案", "洗钱", "拘留", "停用", "注销",
                 "无法派送", "欠税", "包裹被扣", "快递被扣", "出车祸", "出事了", "被抓"],
    "secrecy": ["不要告诉", "别告诉", "不要跟别人说", "保密", "不能告诉", "不要声张"],
    "impersonation": ["公安局", "警察", "警官", "检察院", "法院", "大使馆", "领事馆", "领事处", "国税局", "税务局", "移民局",
                      "社安局", "海关", "银行客服", "快递客服", "官方客服", "社保局", "医保局"],
    "windfall": ["中奖", "大奖", "奖金", "退税", "双倍赔偿", "补偿金", "遗产", "放款", "审批通过", "预授信"],
    "investment": ["高回报", "高收益", "稳赚", "保本", "保证收益", "收益翻倍", "资金翻倍", "内幕", "带单", "投资群", "荐股", "老师带",
                   "财富自由", "每日收益", "日收益", "做黄金", "炒黄金", "交易平台"],
    "task": ["刷单", "做任务", "返利", "返佣", "佣金", "日赚", "点赞赚钱", "垫资"],
    "health": ["神药", "根治", "包治", "特效药", "祖传秘方", "无效退款"],
}
# Asks that are ordinary words on honest notices ("请到柜台付款", "扫码看菜单", "购物卡请到前台办理"): they count
# only next to a lure or a suspicious link.
# Fix round (OC-2): ordinary billing words, shop urgency, "late fees" and staff mentions are weak too:
# bills, receipts, flyers and community notices are full of them ("Amount due ... late fees apply",
# "仅限今天", "工作人员会联系您"). A weak sign counts only next to a real lure or a suspicious link.
_EN_WEAK = {"ask_click": [r"\bscan (?:the |this |our )?(?:qr|code)\b"],
            "ask_money": [r"\bpay\b[^.!?\n]{0,40}(?:\b(?:payment|fee|fine|amount|balance|tax|deposit|penalty|toll|"
                          r"charge|premium|money|cash)s?\b|\$\s?\d)",
                          r"\b(?:amount|balance) (?:due|owed|outstanding)\b",
                          r"\b(?:outstanding|unpaid|overdue) (?:toll|balance|fee|invoice|bill|tax)",
                          r"\bscan (?:the|this) (?:qr )?code to pay\b", r"\bpay (?:now|today|here)\b",
                          r"\bservice (?:fee|charge)s?\b"],
            "pressure": [r"\bimmediately\b", r"\bwithin \d{1,3} days\b", r"\blate fees?\b", r"\bpenalt(?:y|ies)\b", r"\b(?:today|now) only\b",
                         r"\bexpires? (?:today|tonight|soon|in)\b", r"\bon hold\b", r"\bfinal (?:notice|reminder)\b",
                         r"\bavoid (?:penalt(?:y|ies)|late fees?)\b"],
            "impersonation": [r"\b(?:embassy|consulate)\b"]}
_ZH_WEAK = {"ask_money": ["付款", "缴纳", "缴费", "交纳", "押金", "付款码", "欠费", "充值", "资金转入", "转入", "补缴",
                          "交钱", "应付金额"],
            "ask_giftcard": ["礼品卡", "购物卡", "充值卡", "点卡", "苹果卡"],
            "ask_click": ["扫码", "点击", "扫一扫"],
            "pressure": ["立即", "立刻", "马上", "尽快", "限期", "否则", "滞纳金", "限购", "仅限今天", "最后通知"],
            "impersonation": ["工作人员"],
            "windfall": ["退款", "理赔", "补贴", "领取"]}
_EN_RE = {k: [re.compile(p, _I) for p in v] for k, v in _EN.items()}
_ZH_RE = {k: re.compile("|".join(re.escape(w) for w in v), _I) for k, v in _ZH.items()}
_EN_WEAK_RE = {k: [re.compile(p, _I) for p in v] for k, v in _EN_WEAK.items()}
_ZH_WEAK_RE = {k: re.compile("|".join(re.escape(w) for w in v), _I) for k, v in _ZH_WEAK.items()}
_ZH_NUM = "[一二两三四五六七八九十百千万0-9]"
# "先转两万五", "汇5000", "爷爷，是我": a transfer with an amount, a relative's voice
_ZH_EXTRA = {"ask_money": re.compile(f"(?:转|汇|打|充|交)(?:给我|过来)?{_ZH_NUM}{{1,6}}(?:块|元|万|千)?"),
             "ask_contact": re.compile(r"按\s?[0-9]|(?:联系|拨打|致电|打电话给?|回电)[^。！？\n]{0,10}\d{3}"),
             "ask_giftcard": re.compile(r"(?:买|购买|充值|拍|刮开)[^。！？\n]{0,12}(?:礼品卡|购物卡|充值卡|点卡|苹果卡|卡密)"
                                        r"|(?:礼品卡|购物卡|充值卡|点卡|苹果卡)[^。！？\n]{0,6}(?:拍照?|卡号|卡密|刮开)"),
             "ask_money#2": re.compile(r"放款前[^。！？\n]{0,4}(?:缴|交|付|充|转)"),
             "impersonation": re.compile(r"(?:爷爷|奶奶|外公|外婆|姥姥|姥爷|爸|妈)[，, ]?(?:是)?我(?!们)"
                                         r"|(?:支付宝|微信|淘宝|京东|银行|快递|官方)\s?客服")}
# Secrets count as an ASK only next to a request verb ("把验证码发给我"), not when someone mentions
# their own password ("我行不会索要密码" is a bank's standard line, not an ask).
_ZH_SECRET_N = "验证码|动态码|校验码|密码|身份证号|身份证号码|银行卡号|卡号|社安号|社会安全号|安全码|助记词|私钥"
_ZH_SECRET_V = "告诉|发给|发送|发过来|提供|输入|填写|填入|报给|报一下|说出|念给|念一下|给我|给他|给她|给对方|转发|截图|发我"
_ZH_RE["ask_secret"] = re.compile(f"(?:{_ZH_SECRET_V})[^。！？\n]{{0,15}}(?:{_ZH_SECRET_N})"
                                  f"|(?:{_ZH_SECRET_N})[^。！？\n]{{0,15}}(?:{_ZH_SECRET_V})")
# Negated advice ("Police never ask for gift cards", "公检法不会电话办案", "不收费") is how warning posters and
# honest notices read; a phrase right after a negation does not count.
_NEG_EN = re.compile(r"\b(?:never|not|no|don'?t|doesn'?t|won'?t|will not|do not|does not|cannot)\b[^.!?\n]{0,60}$", _I)
_NEG_ZH = re.compile(r"(?:不会|不要求|不收|没有|无需|不会通过|绝不|从不|不得|谨防|警惕|小心|防范|免)[^。！？\n]{0,12}$")

# ---- indicators
# Links are found with a linear scan (fix round OC-6): runs of URL characters, then each run is split and
# checked in Python. The old single regex backtracked quadratically on dotted runs ("aa." x 6667: 3 s).
_URL_TLDS = {"com", "net", "org", "info", "top", "xyz", "shop", "online", "site", "club", "vip", "cc", "io", "co", "me",
             "ly", "gl", "gd", "link", "click", "live", "app", "cn", "hk", "tk", "ml", "ga", "cf", "ru", "us", "biz"}
_URL_RUN = re.compile(r"[A-Za-z0-9._~:/?#\[\]@!$&*+,;=%-]+")
_URL_SCHEME = re.compile(r"(?i)(?<![a-z])(?:https?://|www\.)")
_HOST_PIECE = re.compile(r"[A-Za-z0-9.-]+")
_LABEL = re.compile(r"[a-z0-9-]{1,63}", _I)
_MAX_URLS = 200
# Lookbehinds make every pattern start only at the beginning of a run, so a long run is read once
# (fix round OC-6: "1," x 10,000 took 5 s in the amount pattern).
_EMAIL_RE = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,8}"
                       r"\.[A-Za-z]{2,24}\b")
_PHONE_RE = re.compile(r"(?<![\w.])(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}(?![\w.])"
                       r"|(?<![\w.])\d{3}[\s.-]\d{4}(?![\w.])|(?<!\d)1[3-9]\d{9}(?!\d)|(?<![\w.])\+\d{8,15}(?!\d)")
_CRYPTO_RE = re.compile(r"\b(?:bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40}|"
                        r"T[1-9A-HJ-NP-Za-km-z]{33})\b")
_MONEY_RE = re.compile(r"[$¥￥€£]\s?\d[\d,.]{0,30}|(?<![\d,.])\d[\d,.]{0,30}\s?(?:dollars|usd|美元|美金|元|万元|块)"
                       r"|(?<![一二两三四五六七八九十百千万])[一二两三四五六七八九十百千万]{1,12}(?:块|元|万)", _I)
_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "t.ly", "s.id", "tiny.cc",
               "ow.ly", "buff.ly", "rebrand.ly", "shorturl.at", "v.gd", "lnkd.in", "t.cn", "dwz.cn", "url.cn"}
_BRANDS = ("paypal", "amazon", "apple", "icloud", "microsoft", "google", "gmail", "netflix", "wellsfargo", "chase",
           "bankofamerica", "citi", "usps", "fedex", "ups", "dhl", "irs", "ssa", "medicare", "coinbase", "binance",
           "telegram", "whatsapp", "wechat", "alipay")
_OFFICIAL = {"paypal.com", "amazon.com", "apple.com", "icloud.com", "microsoft.com", "google.com", "gmail.com",
             "netflix.com", "wellsfargo.com", "chase.com", "bankofamerica.com", "citi.com", "citibank.com", "usps.com",
             "fedex.com", "ups.com", "dhl.com", "irs.gov", "ssa.gov", "medicare.gov", "coinbase.com", "binance.com",
             "telegram.org", "t.me", "whatsapp.com", "wechat.com", "alipay.com"}
_RISKY_TLDS = {"top", "xyz", "shop", "online", "site", "club", "vip", "click", "link", "live", "tk", "ml", "ga", "cf",
               "gd", "ru"}
_CJK = r"\u3000-\u303f\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\uff00-\uffef"
_CJK_GAP = re.compile(f"(?<=[{_CJK}])[ \\t]+(?=[{_CJK}])")
# a line break inside a sentence (OCR and narrow screenshots wrap lines): joined, so phrases and the
# "never ..." before them are read whole. A line that ends in sentence punctuation stays a break.
_WRAP_CJK = re.compile(f"(?<=[{_CJK}])[ \\t]*\\n[ \\t]*(?=[{_CJK}])")
_WRAP = re.compile(r"(?<![.!?:;。！？：；\n])[ \t]*\n[ \t]*(?=\S)")


def tidy(text: str) -> str:
    """Normalise for matching: NFKC (fullwidth -> ASCII), no format characters, no spaces between
    Chinese characters (OCR engines put a space between every character: "点 击 链 接"), and wrapped
    lines joined."""
    t = unicodedata.normalize("NFKC", (text or "")[:MAX_CHARS])
    t = "".join(ch for ch in t if unicodedata.category(ch) != "Cf")
    t = _CJK_GAP.sub("", t)
    t = _WRAP_CJK.sub("", t)
    return _WRAP.sub(" ", t)


def _host(url: str) -> str:
    u = url if "://" in url else "http://" + url
    try:
        return (urlsplit(u).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _registrable(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "gov", "net") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _is_host(piece: str) -> bool:
    labels = piece.split(".")
    if len(labels) < 2 or labels[-1].lower() not in _URL_TLDS:
        return False
    if len(labels[0]) < 2 or not labels[0][:1].isalnum():
        return False
    return all(len(lb) >= 2 and _LABEL.fullmatch(lb) for lb in labels[:-1])


def find_urls(t: str) -> list[str]:
    """Links in the text: scheme or www. links to the end of the run, else bare host names with a known
    ending. Linear in the text length (each character is looked at a fixed number of times)."""
    out: list[str] = []
    for run in _URL_RUN.finditer(t):
        tok = run.group(0)
        m = _URL_SCHEME.search(tok)
        if m:
            out.append(tok[m.start():].rstrip(".,;:!?*"))
        elif "@" not in tok:                       # e-mail addresses are counted on their own
            for p in _HOST_PIECE.finditer(tok.split("/", 1)[0]):
                piece = p.group(0).strip(".-")
                if _is_host(piece):
                    out.append(piece)
                    break
        if len(out) >= _MAX_URLS:
            break
    return out


def link_flags(url: str) -> list[str]:
    """Why a link looks suspicious (empty = nothing found)."""
    host = _host(url)
    if not host:
        return []
    flags = []
    reg = _registrable(host)
    if reg in _SHORTENERS or host in _SHORTENERS:
        flags.append("shortener")
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        flags.append("ip-address")
    if "xn--" in host:
        flags.append("punycode")
    if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
        flags.append("userinfo")
    squashed = host.replace("-", "").replace(".", "").translate(str.maketrans("013457", "oleast"))  # paypa1
    if reg not in _OFFICIAL and any(b in squashed for b in _BRANDS) and not any(host.endswith("." + o) or host == o
                                                                                   for o in _OFFICIAL):
        flags.append("look-alike")
    if host.rsplit(".", 1)[-1] in _RISKY_TLDS:
        flags.append("risky-tld")
    return flags


@dataclass
class Assessment:
    level: str = "none"
    categories: list = field(default_factory=list)
    indicators: dict = field(default_factory=dict)

    @property
    def rank(self) -> int:
        return LEVELS.index(self.level)


def _negated(t: str, start: int, zh: bool) -> bool:
    before = t[max(0, start - 80):start]
    return bool((_NEG_ZH if zh else _NEG_EN).search(before))


def _found(rx, t: str, zh: bool) -> bool:
    for m in rx.finditer(t):
        if not _negated(t, m.start(), zh):
            return True
    return False


def assess(text: str) -> Assessment:
    t = tidy(text)
    hits: set = set()                            # raw keys, e.g. "ask_click#verify"
    for k, pats in _EN_RE.items():
        if any(_found(p, t, False) for p in pats):
            hits.add(k)
    for k, rx in list(_ZH_RE.items()) + list(_ZH_EXTRA.items()):
        if _found(rx, t, True):
            hits.add(k)
    cats = {k.split("#")[0] for k in hits}
    verify = "ask_click#verify" in hits
    safe = "ask_money#safe" in hits
    weak = {k for k, pats in _EN_WEAK_RE.items() if any(_found(p, t, False) for p in pats)}
    weak |= {k for k, rx in _ZH_WEAK_RE.items() if _found(rx, t, True)}
    emails = _EMAIL_RE.findall(t)
    urls = find_urls(t)
    phones = _PHONE_RE.findall(t)
    crypto = _CRYPTO_RE.findall(t)
    money = _MONEY_RE.findall(t)
    bad_links = [u for u in urls[:50] if link_flags(u)]
    ind = {k: n for k, n in (("links", len(urls)), ("suspicious_links", len(bad_links)), ("phones", len(phones)),
                             ("emails", len(emails)), ("crypto_addresses", len(crypto)), ("amounts", len(money))) if n}
    if crypto:
        cats.add("crypto_address")
    if bad_links:
        cats.add("suspicious_link")
    strong = cats & set(LURES)                   # lures from the strong phrase lists only
    redirect = "ask_money" in cats               # payment redirection (strong ask_money phrases only)
    if strong or bad_links or redirect:
        cats |= weak                             # weak signs count only next to a real sign
    # a payment or tap request with a clickable link (the text-message toll / parcel shape): warning signs,
    # never "likely scam" on its own. Bills print bare web addresses ("pay online at city.gov"), not links.
    pay_by_link = any(u[:4].lower() in ("http", "www.") for u in urls) and bool({"ask_money", "ask_click"} & weak)
    if pay_by_link:
        cats |= weak & {"ask_money", "ask_click"}
    sig = _Signs(asks=cats & set(ASKS), lures=cats & set(LURES), strong=strong, redirect=redirect, verify=verify,
                 safe=safe, money=_big_amount(money),
                 crypto=bool(crypto), bad_links=bool(bad_links), links=bool(urls), contact=bool(urls or phones or emails),
                 pay_by_link=pay_by_link)
    return Assessment(_level(sig), [c for c in ORDER if c in cats], ind)


def _big_amount(found: list) -> bool:
    """An amount of 100 or more (any currency) among the matches: the size of a "refund" or "prize" that
    a scan offers, unlike a shop's $5 reward."""
    for m in found[:50]:
        digits = "".join(ch for ch in m.split(".")[0] if ch.isdigit())
        if digits and int(digits[:9]) >= 100 or any(w in m for w in ("百", "千", "万")):
            return True
    return False


@dataclass
class _Signs:
    asks: set
    lures: set
    strong: set
    redirect: bool
    verify: bool
    safe: bool
    money: bool
    crypto: bool
    bad_links: bool
    links: bool
    contact: bool
    pay_by_link: bool


_STRONG_ASKS = {"ask_secret", "ask_giftcard", "ask_remote", "ask_crypto"}


def _level(s: _Signs) -> str:
    """Fix round (OC-2): "likely scam" needs an ask that honest notices do not make, or a real lure together
    with payment redirection, impersonation or a log-in link. One warning word, a phone number and an
    amount (every bill has those) are not enough."""
    pressure = "pressure" in s.strong
    other_asks = s.asks - {"ask_money"}
    if (s.crypto or _STRONG_ASKS & s.asks                              # codes, gift cards, crypto, remote access
            or (s.bad_links and (s.asks or s.lures))                   # a suspicious link that asks or pushes
            or (s.verify and s.links)                                  # "verify your account at <link>"
            or s.safe                                                  # "move your money to a safe account"
            or (s.redirect and (s.lures or s.links))                   # money moved: with a lure, or by link
            or ("impersonation" in s.strong and (pressure or s.redirect or "secrecy" in s.lures
                                                 or {"ask_click", "ask_secret"} & s.asks))
            or ("secrecy" in s.strong and s.asks)                      # "send it, and don't tell anyone"
            or ({"health", "investment", "task"} & s.strong and (s.asks or s.contact or "pressure" in s.lures))
            # "scan to receive your $399 refund": the QR code is the link (OCR does not read it)
            or ("windfall" in s.strong and (("ask_click" in s.asks and (s.links or s.money))
                                            or (pressure and other_asks)))
            or (pressure and "ask_click" in s.asks and s.contact)       # "account locked: click here"
            or len(s.strong) >= 3):
        return "high"
    if ((s.asks - {"ask_contact"}) or s.pay_by_link or len(s.lures) >= 2 or s.bad_links
            or (s.strong and (s.contact or s.asks))):
        return "medium"
    if s.lures:
        return "low"
    return "none"
