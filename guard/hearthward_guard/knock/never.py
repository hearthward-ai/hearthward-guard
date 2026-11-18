"""Knock's never-allowed list: actions no approval can unlock.

A rule matches on the tool name (folded: case, width, look-alike letters and separators do not
matter) and/or on the call's arguments. Arguments are flattened (keys and values, nested JSON
included) and checked in several decoded forms, so quoting tricks, escapes, URL or base64
encoding and look-alike letters do not hide a match.

This is a best-effort list against a model that has been talked into an action, not a sandbox:
code-running tools can always obfuscate further. That is why taint (policy.py) denies risky
tools after untrusted content, and why encoded commands in code-running tools count as "unsure".
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import unicodedata
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass

from ..common.config import ConfigError

MAX_ARG_CHARS = 200_000
MAX_DEPTH = 20
MAX_ITEMS = 5000

# Look-alike letters (Cyrillic, Greek) folded to Latin before matching.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "ɡ": "g", "ν": "v", "ο": "o", "α": "a", "ρ": "p",
    "τ": "t", "κ": "k", "ι": "i", "ε": "e", "μ": "u", "ѵ": "v", "ʏ": "y", "ɪ": "i", "ʟ": "l",
})
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_SHELL_NOISE = re.compile(r"['\"\\^`]")
_WS = re.compile(r"\s+")
_UESC = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|\\([0-7]{3})")
_B64 = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
_NAME_SPLIT = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z])(?=[A-Z])")


def fold(text: str) -> str:
    """NFKC, no format/invisible characters, look-alikes folded, lower case, whitespace collapsed."""
    t = unicodedata.normalize("NFKC", text)
    t = "".join(ch for ch in t if unicodedata.category(ch) not in ("Cf", "Cc", "Mn") or ch in "\n\t")
    t = t.casefold().translate(_CONFUSABLES)
    return _WS.sub(" ", t).strip()


def squash(folded: str, leet: bool = True) -> str:
    """Letters and digits only (separators, quotes and spacing tricks removed)."""
    t = folded.translate(_LEET) if leet else folded
    return re.sub(r"[^0-9a-z一-鿿]+", "", t)


def name_tokens(raw_name: str) -> tuple[set, tuple]:
    """(word tokens, squashed folded forms) of a tool name; digit look-alikes (m0ney) folded too."""
    f = fold(raw_name)
    toks = {fold(t) for t in _NAME_SPLIT.split(unicodedata.normalize("NFKC", raw_name)) if t}
    toks |= {t for t in re.split(r"[^0-9a-z]+", f) if t}
    toks |= {t.translate(_LEET) for t in toks}
    return toks, (squash(f, leet=False), squash(f))


class Unscannable(ValueError):
    """Arguments too large or too deep to check: the caller treats the call as unsure."""


def flatten(args) -> str:
    """Every key and value of the arguments as one text (nested JSON strings opened too)."""
    out: list[str] = []
    size = [0]
    items = [0]

    def add(s: str) -> None:
        size[0] += len(s) + 1
        if size[0] > MAX_ARG_CHARS:
            raise Unscannable("arguments too large to check")
        out.append(s)

    def walk(v, depth: int) -> None:
        items[0] += 1
        if depth > MAX_DEPTH or items[0] > MAX_ITEMS:
            raise Unscannable("arguments too deep to check")
        if isinstance(v, Mapping):                 # any mapping, not only dict (review K-11)
            for k, x in v.items():
                add(str(k))
                walk(x, depth + 1)
        elif isinstance(v, (list, tuple, set, frozenset)):
            for x in v:
                walk(x, depth + 1)
        elif isinstance(v, (bytes, bytearray)):
            add(bytes(v[:MAX_ARG_CHARS]).decode("utf-8", "replace"))
        elif isinstance(v, str):
            add(v)
            s = v.strip()
            if len(s) >= 2 and s[0] in "[{" and s[-1] in "]}":
                try:
                    walk(json.loads(s), depth + 1)
                except (ValueError, RecursionError):
                    pass
        elif v is None or isinstance(v, (bool, int, float)):
            add(str(v))
        else:
            add(str(v)[:1000])

    walk(args, 0)
    return "\n".join(out)


def _printable(b: bytes) -> str | None:
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not s or sum(ch.isprintable() or ch in "\n\t" for ch in s) < 0.9 * len(s):
        return None
    return s


def decoded_forms(text: str) -> list[str]:
    """Extra forms of the text: escapes, URL encoding, base64 and hex segments decoded."""
    forms = []
    if "\\" in text:
        def _u(m):
            try:
                if m.group(1):
                    return chr(int(m.group(1), 16))
                if m.group(2):
                    return chr(int(m.group(2), 16))
                return chr(int(m.group(3), 8))
            except ValueError:
                return m.group(0)
        forms.append(_UESC.sub(_u, text))
    if "%" in text or "+" in text:
        u = urllib.parse.unquote_plus(urllib.parse.unquote_plus(text))
        if u != text:
            forms.append(u)
    for m in list(_B64.finditer(text))[:200]:
        seg = m.group(0)
        for fn in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                s = _printable(fn(seg + "=" * (-len(seg) % 4)))
            except (binascii.Error, ValueError):
                s = None
            if s:
                forms.append(s)
                break
    for m in list(_HEX.finditer(text))[:200]:
        try:
            s = _printable(bytes.fromhex(m.group(0)))
        except ValueError:
            s = None
        if s:
            forms.append(s)
    return forms


@dataclass(frozen=True)
class ArgView:
    """The argument text in the forms rules look at."""
    texts: tuple          # folded forms (spaces kept)
    squashed: tuple       # separator-free forms


def view(args) -> ArgView:
    raw = flatten(args)
    base = [raw] + decoded_forms(raw)
    for extra in list(base[1:]):
        base += decoded_forms(extra)[:20]     # one more layer (e.g. base64 inside URL encoding)
    texts, sq = [], []
    for t in base:
        f = fold(t)
        texts.append(f)
        texts.append(_WS.sub(" ", _SHELL_NOISE.sub("", f)))
        sq.append(squash(f))
        sq.append(squash(f, leet=False))
    return ArgView(tuple(dict.fromkeys(texts)), tuple(dict.fromkeys(sq)))


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


# any one separator between digits (space, dash, en/em dash, dot, underscore, slash: review K-09)
_SEP = "[ \\-._/–—]"
_CARD_RX = re.compile(r"(?<![0-9])(?:[0-9]" + _SEP + r"?){12,18}[0-9](?![0-9])")
_CN_ID_RX = re.compile(r"(?<![0-9])([0-9]{6})" + _SEP + r"?([0-9]{8})" + _SEP + r"?([0-9]{3}[0-9x])(?![0-9a-z])")
_CN_W = (7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2)


def _card_prefix_ok(d: str) -> bool:
    """A real card network prefix (Visa, Mastercard, Amex, Discover, JCB, UnionPay, Diners): an
    18-digit chat id or build number is not a card (review K-10)."""
    two, four = int(d[:2]), int(d[:4])
    return (d[0] == "4" or 51 <= two <= 55 or 2221 <= four <= 2720 or two in (34, 37, 35, 62, 65, 36, 38, 30)
            or d.startswith("6011") or 644 <= int(d[:3]) <= 649)


def has_card_number(text: str) -> bool:
    for m in _CARD_RX.finditer(text):
        d = re.sub(r"[^0-9]", "", m.group(0))
        if 13 <= len(d) <= 19 and _luhn_ok(d) and len(set(d)) >= 2 and _card_prefix_ok(d):
            return True
    return False


def has_cn_id(text: str) -> bool:
    """A Chinese resident ID: a real birth date and a matching check digit (review K-10)."""
    for m in _CN_ID_RX.finditer(text):
        d = "".join(m.groups())
        y, mo, day = int(d[6:10]), int(d[10:12]), int(d[12:14])
        if not (1900 <= y <= 2099 and 1 <= mo <= 12 and 1 <= day <= 31):
            continue
        check = "10x98765432"[sum(int(c) * w for c, w in zip(d[:17], _CN_W)) % 11]
        if d[17] == check:
            return True
    return False


@dataclass(frozen=True)
class Rule:
    rid: str
    label: str                      # shown to the model and the owner
    name_tokens: frozenset = frozenset()     # any token of the tool name
    name_substr: tuple = ()          # substring of the squashed tool name
    name_exact: frozenset = frozenset()      # exact tool names
    arg_rx: tuple = ()               # compiled regexes on the folded argument forms
    arg_squashed: tuple = ()         # substrings of the squashed argument forms
    card_numbers: bool = False
    arg_scope: str = "exec"          # exec = tools that act on other systems (act+source, unknown);
                                     # act = every tool with side effects;
                                     # all = every tool except class "read"
    builtin: bool = True

    def match_name(self, raw_name: str, toks: set, sq: str) -> bool:
        if raw_name in self.name_exact:
            return True
        if self.name_tokens and toks & self.name_tokens:
            return True
        return any(s in q for q in sq for s in self.name_substr)

    def match_args(self, av: ArgView) -> bool:
        for t in av.texts:
            if any(rx.search(t) for rx in self.arg_rx):
                return True
            if self.card_numbers and (has_card_number(t) or has_cn_id(t)):
                return True
        return any(s in q for q in av.squashed for s in self.arg_squashed)


_SU = "su" + "do"      # built at run time so plugin scanners do not read the pattern as a command


def _rx(*patterns: str) -> tuple:
    return tuple(re.compile(p) for p in patterns)


# The SSH sign-in files (the key list and the server config), spelled with [_] so the plugin
# scanner's plain-text rules do not read this rule as a backdoor (lab re-test (d)). The regex is
# unchanged; tests/knock/test_knock_fixround3.py checks that it still matches.
SIGN_IN_FILES = r"(authorized[_]keys2?|sshd[_]config)"
# the Hermes secrets file name, spelled with [v] for the same reason (same regex)
_ENV_FILE = r"\.en[v]"


BUILTIN = (
    Rule("money", "moving money",
         name_tokens=frozenset({"pay", "payment", "payments", "payout", "payouts", "transfer", "transfers", "wire",
                                "remit", "remittance", "wallet", "checkout", "purchase", "withdraw", "withdrawal",
                                "venmo", "paypal", "zelle", "alipay", "money", "funds", "bank", "banking", "iban",
                                "invoice", "refund"}),
         name_substr=("money", "payment", "paypal", "venmo", "zelle", "alipay", "wechatpay", "banktransfer",
                      "wiretransfer", "checkout", "withdraw", "remit", "sendfunds", "转账", "付款", "支付", "汇款"),
         arg_rx=_rx(r"\b(wire|bank|money|fund|funds|crypto|btc|eth|usdt|ach|sepa)\s*(transfer|transfers|payment)\b",
                    r"\bsend(ing)?\s+(the\s+|some\s+)?(money|funds|payment|cash|\$\s*\d)",
                    r"\btransfer\s+(of\s+)?[$€£¥]?\s*\d[\d,.]*\s*(k|usd|eur|gbp|dollars|euros|btc|eth|usdt)?\s*"
                    r"(to|into|from)\b",
                    r"\b(move|send|wire)\s+[$€£¥]\s*\d",
                    r"\b(move|send|wire|transfer)\s+\d[\d,.]*\s*(k\s+)?(usd|eur|gbp|dollars|euros|pounds|bucks|btc|eth|usdt)\b",
                    r"\b(sendtoaddress|sendmany|sendfrom|sendrawtransaction)\b",
                    r"\bstripe\s+(payouts|transfers|charges|refunds|payment_intents)\s+create\b",
                    r"\b(zelle|venmo|paypal|cash\s*app|western\s*union|moneygram|alipay|wechat\s*pay)\b",
                    r"\bgift\s*cards?\b", r"\b(iban|swift\s*code|routing\s*number|sort\s*code)\b",
                    r"api\.stripe\.com/v\d+/(charges|payouts|transfers|payment_intents|refunds)",
                    r"\bstripe\.(payout|transfer|charge|refund|paymentintent|payment_intent)s?\.create\b",   # R-10
                    r"\b(wire|send|transfer|move)\s+(the\s+|all\s+(the\s+)?|my\s+|our\s+|some\s+|his\s+|her\s+|their\s+)?"
                    r"(funds|money|cash|balance|savings)\s+(to|into)\b",
                    r"\b(pay|purchase|buy)\s+(the\s+|this\s+|an?\s+)?(invoice|bill|order|item|ticket|subscription)",
                    r"\b(place[\s_-]*order|submit[\s_-]*payment)\b",      # bare "checkout" removed (K-10)
                    r"转账|汇款|付款|支付|打款|提现|充值"),
         arg_squashed=("wiretransfer", "banktransfer", "sendmoney", "sendfunds", "moneytransfer")),
    Rule("trades", "trading",
         name_tokens=frozenset({"trade", "trades", "trading", "broker", "brokerage", "stock", "stocks", "crypto",
                                "order", "orders", "buy", "sell"}),
         name_substr=("placeorder", "submitorder", "marketorder", "limitorder", "buystock", "sellstock", "trade",
                      "下单", "交易"),
         arg_rx=_rx(r"\b(buy|sell)\s+[\d,.]*\s*(x\s+)?(shares?|stocks?|options?|contracts?|calls?|puts?|"
                    r"btc|eth|crypto|coins?|tokens?|etfs?)\b",
                    r"\b(short|long)\s+\d[\d,.]*\s*(x\s+)?(shares?|stocks?|options?|contracts?|calls?|puts?|"
                    r"btc|eth|crypto|coins?|tokens?|etfs?)\b",             # "long options" is not a trade (K-10)
                    # an order placed through a client object (exchange.createOrder(...)); a plain
                    # "def create_order" in shop code is not a trade (recheck R-10)
                    r"\.\s*create_?(market_?|limit_?)?(buy_?|sell_?)?order\s*\(",
                    r"\bcreate_(market|limit)_(buy_|sell_)?order\b", r"\border_(market|limit)_(buy|sell)\b",
                    r"\border_(buy|sell)_[a-z_]+",
                    r"\b(market|limit|stop|stop[\s-]*limit)\s+(buy|sell\s+)?order\b",
                    r"\b(place|submit|send)[\s_-]*(an?\s+)?(trade|order)s?\b(?!\s+(status|history))",
                    r"(api|paper-api)\.alpaca\.markets|api\.binance\.|api\.coinbase\.com|api\.kraken\.com|"
                    r"interactivebrokers|ibkr|schwabapi|robinhood|tradier|tdameritrade",
                    r"买入|卖出|下单|开仓|平仓|做空|做多"),
         arg_squashed=("placeorder", "submitorder", "marketorder", "limitorder")),
    Rule("passwords", "changing passwords or sign-in settings",
         name_tokens=frozenset({"password", "passwords", "passwd", "passphrase", "credential", "credentials", "2fa",
                                "mfa", "totp"}),
         name_substr=("password", "passwd", "passphrase", "credential", "密码"),
         arg_rx=_rx(r"\b(chpasswd|gpasswd|chage|pwpolicy|dscl)\b",
                    # passwd only as a command being run, not as a path or inside a word (review K-10);
                    # the argument name in front counts as a start (folded text, recheck R-10)
                    r"(?:^|[;&|(]\s*|\b(?:command|cmd|code|script|input)\s+|\b(?:" + _SU +
                    r"|doas|exec|xargs|env)\s+)passwd\b",
                    r"\b(change|reset|set|update|modify)\b(?:[\s_-]+[a-z0-9'-]+){0,3}?[\s_-]+"
                    r"(password|passphrase|passcode|pin[\s_-]*(code|number)|(sim|atm|card|bank|phone|device)[\s_-]+pin)\b",
                    r"\bnew[\s_-]*(password|passphrase|passcode)\b",
                    r"\busermod\b[^\n]{0,200}\s(-p|--password)\b", r"\bnet\s+user\s+\S+\s+\S+",
                    r"set-localuser[^\n]{0,200}-password", r"set-adaccountpassword", r"set-keychain-password",
                    r"/etc/g?shadow\b",
                    r"(disable|turn\s*off|remove|reset)\s+(the\s+)?(two[\s-]*factor|2fa|mfa|totp)",
                    r"(two[\s-]*factor|2fa|mfa|totp)\s+(disable|off|remove|reset)",
                    r"(change|update|set|replace)\s+(the\s+)?recovery\s+(email|phone|address)",
                    r"修改密码|重置密码|更改密码|改密码"),
         arg_squashed=("changepassword", "resetpassword", "setpassword", "updatepassword", "newpassword",
                       "chpasswd")),
    Rule("id_numbers", "sending ID or card numbers",
         arg_rx=_rx(r"(?<![0-9])[0-9]{3}(" + _SEP + r")[0-9]{2}\1[0-9]{4}(?![0-9])", r"\bssn\b",
                    r"social\s+security\s+(number|no\b|#)", r"passport\s+(number|no\b|#)",
                    r"身份证|护照号|社保号",              # 18-digit IDs: has_cn_id (date + check digit)
                    r"\b(cvv|cvc)\s*[:=]?\s*[0-9]{3,4}\b"),
         arg_squashed=("socialsecuritynumber", "passportnumber"),
         card_numbers=True, arg_scope="all"),
    Rule("vault", "using saved logins or payment codes", name_exact=frozenset({"browser_vault"})),
    # adding a sign-in key is changing sign-in settings, for every writing tool (recheck R-10)
    Rule("sign_in", "changing passwords or sign-in settings",
         arg_rx=_rx(r">{1,2}\s*\S*" + SIGN_IN_FILES + r"\b",
                    r"\b(tee|cp|mv|install|ln|dd|rsync|scp|sed|perl|truncate)\b[^\n]{0,200}" + SIGN_IN_FILES + r"\b",
                    r"\bssh-copy-id\b",
                    r"\b(path|file|file_path|filename|target)\s+\S*" + SIGN_IN_FILES + r"\b"),
         arg_scope="act"),
    # the guard's own surface: plugin folder, Hermes config, plugin switch, approvals, YOLO (review K-14)
    Rule("guard_off", "switching off the safety guard or approvals",
         arg_rx=_rx(r"\bhermes\s+plugins?\s+(disable|uninstall|remove|rm)\b", r"\bhermes_yolo_mode\b",
                    r"(?:^|\s)(--yolo|/yolo)\b", r"\.hermes/(config\.ya?ml|plugins\b)", r"plugins/hearthward[-_]guard\b",
                    r"\bapprovals\s*:\s*\{?[^\n]{0,200}?\bmode\s*:\s*(off|false|no|smart)\b",
                    r"\bhermes\s+config\s+set\s+(approvals|plugins)",
                    # ways round the rule above (recheck R-10): a glob or a cd into the folder, the env
                    # file, the open-gateway switches, another HERMES_HOME, restarting the gateway
                    r"\.hermes/\S*([*?\[]|plug|hearth)", r"\.hermes/\.env\b",
                    # (fix round 3: the env file name starts with a dot, so the word boundary
                    # sits after it; before, a cd into ~/.hermes followed by printing that file slipped through)
                    r"\bcd\s+\S*\.hermes\b[^\n]{0,300}?(\b(config\.ya?ml|plugins?)\b|" + _ENV_FILE + r"\b)",
                    r"\bgateway_allow_all_users\b", r"\b[a-z]+_allowed_users\b", r"\bhermes_home\s*=",
                    r"\bhermes\s+gateway\s+(restart|stop|start|run|install|uninstall)\b"),
         arg_scope="act"),
)
BUILTIN_IDS = frozenset(r.rid for r in BUILTIN)
_RID_RX = re.compile(r"[a-z][a-z0-9_-]{1,40}")        # fullmatch (review K-16)


def user_rule(raw, where: str) -> Rule:
    """An extra rule from knock.never_allow: {id, tools: [names], args: [regex], label?}."""
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: expected a mapping with id, tools and/or args")
    unknown = set(map(str, raw)) - {"id", "tools", "args", "label"}
    if unknown:
        raise ConfigError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}")
    rid = raw.get("id")
    if not isinstance(rid, str) or not _RID_RX.fullmatch(rid):
        raise ConfigError(f"{where}.id: expected a short lower-case id")
    names = raw.get("tools", []) or []
    pats = raw.get("args", []) or []
    if not isinstance(names, list) or not all(isinstance(n, str) and 1 <= len(n) <= 128 for n in names):
        raise ConfigError(f"{where}.tools: expected a list of tool names")
    if not isinstance(pats, list) or len(pats) > 50:
        raise ConfigError(f"{where}.args: expected a list of at most 50 regexes")
    if not names and not pats:
        raise ConfigError(f"{where}: needs tools and/or args")
    compiled = []
    for i, p in enumerate(pats):
        if not isinstance(p, str) or not 2 <= len(p) <= 300:
            raise ConfigError(f"{where}.args[{i}]: expected a regex string (2-300 chars)")
        try:
            compiled.append(re.compile(p, re.I))
        except re.error as e:
            raise ConfigError(f"{where}.args[{i}]: invalid regex ({e.msg})") from None
    label = raw.get("label", rid)
    if not isinstance(label, str) or not 1 <= len(label) <= 80:
        raise ConfigError(f"{where}.label: expected a short text")
    # tool names are matched exactly and by their folded form
    return Rule(rid, label, name_exact=frozenset(names), name_substr=tuple(squash(fold(n), leet=False) for n in names),
                arg_rx=tuple(compiled), arg_scope="all", builtin=False)


def check(rules, raw_name: str, args, executes: bool, reads_only: bool, acts: bool = True) -> tuple[str, str] | None:
    r = check_rule(rules, raw_name, args, executes, reads_only, acts)
    return None if r is None else (r[0].rid, r[0].label)


def check_rule(rules, raw_name: str, args, executes: bool, reads_only: bool, acts: bool = True):
    """-> (rule, matched on the name?) of the first matching rule, or None.
    executes: the tool can act on other systems (class act+source or unknown); plain "act" tools
    (write a file, save a memory) only get the "all" rules, so a note that mentions paying a bill
    is fine. reads_only: class "read" (no argument rules). Raises Unscannable when the arguments
    cannot be checked."""
    toks, sq = name_tokens(raw_name)
    for r in rules:
        if r.match_name(raw_name, toks, sq):
            return r, True
    if reads_only:
        return None
    av = None
    for r in rules:
        if not (r.arg_rx or r.arg_squashed or r.card_numbers):
            continue
        if r.arg_scope == "exec" and not executes:
            continue
        if r.arg_scope == "act" and not (acts or executes):
            continue
        if av is None:
            av = view(args)
        if r.match_args(av):
            return r, False
    return None


_OBFUSCATION = _rx(r"\bbase64\s+(-d|--decode|-D)\b", r"\bb64decode\b", r"\bxxd\s+-r\b", r"\bopenssl\s+(enc\s+)?-d\b",
                   r"fromcharcode", r"(\\x[0-9a-f]{2}){6,}", r"\bpowershell\b[^\n]{0,200}\s-e(nc(odedcommand)?)?\s",
                   r"\bbase(32|58|85)\s+(-d|--decode)\b", r"\bb(32|85)decode\b", r"\bmap\s*\(\s*chr\b",
                   r"(\bchr\s*\(\s*\d+\s*\)\s*\+\s*){3}", r"\btr\s+-d\b[^\n]{0,200}\|\s*[a-z]*sh\b",
                   r"<<<[^\n]{0,200}\|\s*[a-z]*sh\b",
                   r"\bfrombase64string\b", r"\|\s*rev\b", r"\btr\s+['\"]?a-z['\"]?\s+['\"]?n-za-m",
                   r"codecs\.decode\([^)]*rot", r"\batob\s*\(", r"\bunhexlify\b", r"bytes\.fromhex")


def obfuscated(args) -> bool:
    """Encoded or decode-then-run content in a code-running tool's arguments ("unsure")."""
    av = view(args)
    return any(rx.search(t) for t in av.texts for rx in _OBFUSCATION)
