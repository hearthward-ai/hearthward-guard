#!/usr/bin/env python3
"""Disclosure block: hardware, software and settings behind a result set. Standard library only.
Writes JSON with no paths, user names or host names: the model and the server are named by file name only, and any
absolute path inside the flag line is cut to its file name.

usage: python disclosure.py --out disclosure.json [--server-exe PATH] [--model PATH] [--sha256]
         [--args-file configs/x.args | --flags "..."] [--template builtin|<file name>]
"""
import argparse, hashlib, json, os, platform, re, subprocess, sys

NOWIN = 0x08000000 if os.name == "nt" else 0


def run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, creationflags=NOWIN)
        return ((r.stdout or "") + "\n" + (r.stderr or "")).strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def strip_paths(s):
    """Replace absolute Windows/Unix paths with their last component."""
    s = re.sub(r'(?:[A-Za-z]:)?[\\/](?:[^\s"\\/]+[\\/])+([^\s"\\/]+)', r"\1", s)
    return s


def gpu():
    q = run(["nvidia-smi", "--query-gpu=name,memory.total,driver_version,pcie.link.gen.max,pcie.link.width.max,"
             "pcie.link.gen.current,pcie.link.width.current", "--format=csv,noheader,nounits"])
    out = {}
    if q:
        p = [x.strip() for x in q.splitlines()[0].split(",")]
        out = {"name": p[0], "vram_mib": int(float(p[1])), "driver": p[2], "pcie_gen_max": p[3], "pcie_width_max": p[4],
               "pcie_gen_now": p[5], "pcie_width_now": p[6]}
    m = re.search(r"CUDA (?:UMD )?Version:\s*([\d.]+)", run(["nvidia-smi"]))
    if m:
        out["cuda"] = m.group(1)
    return out


def cpu_ram():
    out = {"os": f"{platform.system()} {platform.release()} build {platform.version()}", "logical_cpus": os.cpu_count()}
    if os.name == "nt":
        ps = ("$c=Get-CimInstance Win32_Processor|Select-Object -First 1 Name,NumberOfCores;"
              "$m=Get-CimInstance Win32_PhysicalMemory;"
              "[pscustomobject]@{cpu=$c.Name.Trim();cores=$c.NumberOfCores;"
              "ram_gb=[math]::Round(($m|Measure-Object Capacity -Sum).Sum/1GB);sticks=@($m).Count;"
              "rated_mts=($m|Select-Object -First 1).Speed;running_mts=($m|Select-Object -First 1).ConfiguredClockSpeed}|ConvertTo-Json")
        try:
            out.update(json.loads(run(["powershell", "-NoProfile", "-Command", ps], 60) or "{}"))
        except ValueError:
            pass
    else:
        try:
            info = open("/proc/cpuinfo").read()
            out["cpu"] = re.search(r"model name\s*:\s*(.+)", info).group(1).strip()
            kb = int(re.search(r"MemTotal:\s*(\d+)", open("/proc/meminfo").read()).group(1))
            out["ram_gb"] = round(kb / 1048576)
        except (OSError, AttributeError):
            pass
    return out


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 24), b""):
            h.update(b)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--server-exe")
    ap.add_argument("--model")
    ap.add_argument("--sha256", action="store_true", help="hash the model file (slow for large files)")
    ap.add_argument("--args-file")
    ap.add_argument("--flags", default="")
    ap.add_argument("--template", default="", help="builtin, or the name of the chat template file used")
    a = ap.parse_args()
    here = os.path.dirname(os.path.abspath(__file__))
    d = {"hardware": {"gpu": gpu(), **cpu_ram()}, "software": {}, "settings": {}}
    if a.server_exe:
        v = run([a.server_exe, "--version"])
        d["software"]["llama_cpp"] = " ".join(l for l in v.splitlines() if l.startswith(("version", "built"))) or v[:200]
    try:
        hp = json.load(open(os.path.join(here, "prompts", "hermes_prompt.json"), encoding="utf-8"))
        d["software"]["hermes_agent"] = {"commit": hp.get("commit"), "source": hp.get("source")}
    except OSError:
        pass
    if a.model:
        d["software"]["model_file"] = os.path.basename(a.model)
        d["software"]["model_bytes"] = os.path.getsize(a.model)
        if a.sha256:
            d["software"]["model_sha256"] = sha256(a.model)
    flags = a.flags
    if a.args_file:
        flags = " ".join(l.strip() for l in open(a.args_file, encoding="utf-8") if l.strip() and not l.startswith("#"))
    d["settings"] = {"flags": strip_paths(flags), "template": strip_paths(a.template),
                     "sampling": {"temperature": 0.6, "top_p": 0.95, "parallel_tool_calls": False, "thinking": "on unless noted"},
                     "electricity_price_usd_kwh": 0.15}
    d["not_measured"] = ["wall power (no meter): GPU board power and CPU package power only", "other GPUs"]
    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
    print(json.dumps(d, ensure_ascii=False, indent=1))


if __name__ == "__main__":
    sys.exit(main())
