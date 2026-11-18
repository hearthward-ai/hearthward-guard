#!/usr/bin/env python3
"""Build prompts/hermes_prompt.json from a Hermes Agent source checkout, WITHOUT running any Hermes code.

Hermes Agent (Nous Research, MIT licence) assembles its system prompt and tool list at run time. This script
approximates the default for a plain chat session statically: it parses the source with `ast` and evaluates only
literal expressions (strings, dicts, lists, concatenation, references to other module-level literals).

  system prompt = the guidance constants in PROMPT_PARTS (agent/prompt_builder.py), joined by blank lines
  tools         = the default core toolset (toolsets.py _HERMES_CORE_TOOLS) minus kanban_*, deferred and
                  service-gated tools, with each schema taken from its tools/*.py registry.register(...) call

Inside tool schemas, names computed at run time become "{NAME}" placeholders (counted in "placeholders").
Tools whose schema is built by a function call are listed under "unresolved" and left out.
The benchmark pads or trims chat history so the total prompt matches a measured real bot turn, so a few missing
tools change the content, not the measured prompt size.

usage: python -I extract_hermes_prompt.py <hermes-checkout> <commit> <out.json>
"""
import ast, json, os, sys

PROMPT_PARTS = ["DEFAULT_AGENT_IDENTITY", "HERMES_AGENT_HELP_GUIDANCE", "SESSION_SEARCH_GUIDANCE", "SKILLS_GUIDANCE",
                "TOOL_USE_ENFORCEMENT_GUIDANCE", "TASK_COMPLETION_GUIDANCE"]
SKIP_TOOLS = {"browser_vault": "deferred by default", "computer_use": "service-gated",
              "manage_connections": "service-gated"}


class Unresolved(Exception):
    pass


def literal(node, env):
    """Evaluate a literal-only expression; names resolve through env (module-level literals)."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id in env:
            return env[node.id]
        raise Unresolved(node.id)
    if isinstance(node, ast.Dict):
        out = {}
        for k, v in zip(node.keys, node.values):
            if k is None:
                out.update(literal(v, env))
            else:
                out[literal(k, env)] = literal(v, env)
        return out
    if isinstance(node, (ast.List, ast.Tuple)):
        return [literal(e, env) for e in node.elts]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return literal(node.left, env) + literal(node.right, env)
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant):
                parts.append(v.value)
                continue
            try:
                parts.append(str(literal(v.value, env)))
            except (Unresolved, TypeError, ValueError):   # computed at run time: keep the placeholder text
                parts.append("{" + ast.unparse(v.value) + "}")
        return "".join(parts)
    if isinstance(node, ast.FormattedValue):
        return str(literal(node.value, env))
    raise Unresolved(type(node).__name__)


class LenientEnv(dict):
    """Names that are computed at run time (imports, function results) become "{NAME}" placeholder text."""
    def __contains__(self, k):
        return True

    missed = set()

    def __missing__(self, k):
        LenientEnv.missed.add(k)
        return "{" + k + "}"


def module_env(tree, lenient=False):
    env = LenientEnv() if lenient else {}
    for st in tree.body:
        if isinstance(st, (ast.Assign, ast.AnnAssign)):
            targets = st.targets if isinstance(st, ast.Assign) else [st.target]
            if st.value is None:
                continue
            try:
                val = literal(st.value, env)
            except (Unresolved, TypeError, ValueError):
                continue
            for t in targets:
                if isinstance(t, ast.Name):
                    env[t.id] = val
    return env


def parse(path):
    with open(path, encoding="utf-8") as f:
        return ast.parse(f.read(), filename=path)


def main(root, commit, out):
    pb = module_env(parse(os.path.join(root, "agent", "prompt_builder.py")))
    missing = [p for p in PROMPT_PARTS if not isinstance(pb.get(p), str)]
    system = "\n\n".join(pb[p] for p in PROMPT_PARTS if isinstance(pb.get(p), str))
    ts = module_env(parse(os.path.join(root, "toolsets.py")))
    core = [t for t in ts["_HERMES_CORE_TOOLS"] if not t.startswith("kanban_") and t not in SKIP_TOOLS]
    schemas, unresolved = {}, {}
    tdir = os.path.join(root, "tools")
    for fn in sorted(os.listdir(tdir)):
        if not fn.endswith(".py"):
            continue
        try:
            tree = parse(os.path.join(tdir, fn))
        except SyntaxError:
            continue
        env = None
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "register"):
                continue
            kw = {k.arg: k.value for k in node.keywords if k.arg}
            if "name" not in kw or "schema" not in kw or not isinstance(kw["name"], ast.Constant):
                continue
            name = kw["name"].value
            if name not in core or name in schemas:
                continue
            env = env if env is not None else module_env(tree, lenient=True)
            try:
                sch = literal(kw["schema"], env)
                if not isinstance(sch, dict) or "parameters" not in sch:
                    raise Unresolved("not a function schema")
                sch.setdefault("name", name)
                schemas[name] = sch
                unresolved.pop(name, None)
            except (Unresolved, TypeError, ValueError) as e:
                unresolved[name] = f"{fn}: built by code ({e})"
    for name in core:
        if name not in schemas and name not in unresolved:
            unresolved[name] = "no literal registry.register() found"
    tools = [{"type": "function", "function": {"name": n, "description": schemas[n].get("description", ""),
                                               "parameters": schemas[n]["parameters"]}} for n in core if n in schemas]
    doc = {
        "source": "Hermes Agent by Nous Research (MIT licence), https://github.com/NousResearch/hermes-agent",
        "commit": commit,
        "licence_note": "Prompt text and tool schemas are copied from Hermes Agent; MIT licence, Copyright (c) 2025 Nous Research; full text in THIRD_PARTY_NOTICES.md at the repo root.",
        "method": "static approximation: guidance constants " + ", ".join(PROMPT_PARTS) +
                  "; default core toolset minus kanban_*, deferred and service-gated tools; literal schemas only",
        "skipped_tools": SKIP_TOOLS, "placeholders": sorted(k for k in LenientEnv.missed if "{" + k + "}" in json.dumps(tools)), "unresolved_tools": unresolved, "missing_prompt_parts": missing,
        "system": system, "tools": tools,
    }
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    print(f"system prompt {len(system)} chars ({len(PROMPT_PARTS) - len(missing)}/{len(PROMPT_PARTS)} parts), "
          f"{len(tools)} tools, unresolved {sorted(unresolved)}")
    return 0 if system and tools else 1


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    sys.exit(main(*sys.argv[1:]))
