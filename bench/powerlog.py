#!/usr/bin/env python3
"""M7: 1 Hz power log. Standard library only. GPU: one long-running nvidia-smi (power, VRAM, utilisation, clock).
CPU package: Windows "Energy Meter" RAPL counter (typeperf), or Linux /sys/class/powercap energy_uj. Each row is
tagged with the current contents of --tag-file (what the benchmark is doing right now). Wall power is NOT measured.

Rows: {"t": unix_s, "tag": str, "gpu_w", "vram_mib", "gpu_util", "sm_mhz", "cpu_w"}
usage: python powerlog.py --out power.jsonl [--tag-file tag.txt] [--seconds N] [--stop-file F]
"""
import argparse, glob, json, os, subprocess, sys, threading, time

NOWIN = 0x08000000 if os.name == "nt" else 0
CPU_COUNTER = r"\Energy Meter(RAPL_Package0_PKG)\Power"   # milliwatts; case-insensitive on Windows


class CpuPower(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.w, self.proc = None, None

    def run(self):
        if os.name == "nt":
            try:
                self.proc = subprocess.Popen(["typeperf", CPU_COUNTER, "-si", "1"], stdout=subprocess.PIPE,
                                             stderr=subprocess.DEVNULL, text=True, creationflags=NOWIN)
                for line in self.proc.stdout:
                    p = line.strip().split('","')
                    if len(p) == 2:
                        try:
                            self.w = float(p[1].strip('"')) / 1000.0
                        except ValueError:
                            pass
            except OSError:
                pass
            return
        files = glob.glob("/sys/class/powercap/*:0/energy_uj")
        if not files:
            return
        last = None
        while True:
            try:
                e, t = int(open(files[0]).read()), time.time()
                if last and e >= last[0]:
                    self.w = (e - last[0]) / 1e6 / (t - last[1])
                last = (e, t)
            except OSError:
                return
            time.sleep(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--tag-file")
    ap.add_argument("--seconds", type=float, default=0, help="0 = until killed or --stop-file appears")
    ap.add_argument("--stop-file")
    a = ap.parse_args()
    cpu = CpuPower()
    cpu.start()
    smi = subprocess.Popen(["nvidia-smi", "--query-gpu=power.draw,memory.used,utilization.gpu,clocks.sm",
                            "--format=csv,noheader,nounits", "-lms", "1000"], stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, text=True, creationflags=NOWIN)
    t0 = time.time()
    try:
        with open(a.out, "a", encoding="utf-8", newline="\n") as f:
            for line in smi.stdout:
                p = [x.strip() for x in line.split(",")]
                if len(p) < 4:
                    continue
                def num(x):
                    try:
                        return float(x)
                    except ValueError:
                        return None
                tag = ""
                if a.tag_file:
                    try:
                        tag = open(a.tag_file, encoding="utf-8").read().strip()
                    except OSError:
                        pass
                row = {"t": round(time.time(), 2), "tag": tag, "gpu_w": num(p[0]), "vram_mib": num(p[1]),
                       "gpu_util": num(p[2]), "sm_mhz": num(p[3]), "cpu_w": None if cpu.w is None else round(cpu.w, 2)}
                f.write(json.dumps(row) + "\n")
                f.flush()
                if (a.seconds and time.time() - t0 >= a.seconds) or (a.stop_file and os.path.exists(a.stop_file)):
                    break
    finally:
        smi.kill()
        if cpu.proc:
            cpu.proc.kill()


if __name__ == "__main__":
    sys.exit(main())
