#!/usr/bin/env python3
from pathlib import Path
import re
import statistics as stats

# ---- Configuration: update paths if your filenames differ ----
# Expected structure (relative to where you run the script):
#  - with            (direct, with xss)
#  - without         (direct, without xss)
#  - proxy/with-xss  (proxy, with xss)
#  - proxy/without-xss (proxy, without xss)
FILE_MAP = {
    ("direct", "no_xss"): Path("without"),
    ("direct", "with_xss"): Path("with"),
    ("proxy",  "no_xss"): Path("proxy/without-xss"),
    ("proxy",  "with_xss"): Path("proxy/with-xss"),
}

NUM_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*$")  # integers or floats per line

def read_latencies(path: Path):
    vals = []
    if not path.exists():
        return vals
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = NUM_RE.match(line)
            if m:
                vals.append(float(m.group(1)))
    return vals

def percentile(values, p):
    if not values:
        return None
    # simple nearest-rank method
    values_sorted = sorted(values)
    k = max(1, int(round(p * len(values_sorted) + 0.5)))
    k = min(k, len(values_sorted))
    return values_sorted[k-1]

def fmt(x, nd=2):
    if x is None: return "-"
    if isinstance(x, float):
        return f"{x:.{nd}f}"
    return str(x)

def main():
    # Load all datasets
    data = {}
    for (net, xss), path in FILE_MAP.items():
        vals = read_latencies(path)
        data[(net, xss)] = vals

    # Build summary rows
    rows = []
    header = ["Network", "xss", "n", "avg_ms", "median_ms", "p95_ms", "min_ms", "max_ms"]
    for (net, xss), vals in data.items():
        n = len(vals)
        avg = stats.mean(vals) if n else None
        med = stats.median(vals) if n else None
        p95 = percentile(vals, 0.95) if n else None
        mn  = min(vals) if n else None
        mx  = max(vals) if n else None
        rows.append([net, "with" if xss=="with_xss" else "without", n, avg, med, p95, mn, mx])

    # Sort rows for a stable, readable layout
    order = {("direct","no_xss"):0, ("direct","with_xss"):1, ("proxy","no_xss"):2, ("proxy","with_xss"):3}
    rows.sort(key=lambda r: order[(r[0], "with_xss" if r[1]=="with" else "no_xss")])

    # Print summary table
    col_widths = [max(len(str(h)), max((len(fmt(r[i])) for r in rows), default=0)) for i,h in enumerate(header)]
    def print_row(vals):
        print("  ".join(str(v).ljust(col_widths[i]) for i,v in enumerate(vals)))

    print("\n=== Latency Summary (ms) ===")
    print_row(header)
    print_row(["-"*w for w in col_widths])
    for r in rows:
        printable = r[:]
        # format numerics nicely
        printable[3] = fmt(printable[3])
        printable[4] = fmt(printable[4])
        printable[5] = fmt(printable[5])
        printable[6] = fmt(printable[6])
        printable[7] = fmt(printable[7])
        print_row(printable)

    # Compute overheads (average deltas)
    def avg(key):
        vals = data.get(key, [])
        return stats.mean(vals) if vals else None

    direct_no   = avg(("direct","no_xss"))
    direct_yes  = avg(("direct","with_xss"))
    proxy_no    = avg(("proxy","no_xss"))
    proxy_yes   = avg(("proxy","with_xss"))

    # Overhead: proxy vs direct, holding xss constant
    proxy_over_no   = (proxy_no - direct_no) if (proxy_no is not None and direct_no is not None) else None
    proxy_over_yes  = (proxy_yes - direct_yes) if (proxy_yes is not None and direct_yes is not None) else None

    # Overhead: xss vs no-xss, holding network constant
    xss_over_direct = (direct_yes - direct_no) if (direct_yes is not None and direct_no is not None) else None
    xss_over_proxy  = (proxy_yes - proxy_no) if (proxy_yes is not None and proxy_no is not None) else None

    print("\n=== Average Overheads (ms) ===")
    over_rows = [
        ["Proxy overhead (no xss):", fmt(proxy_over_no)],
        ["Proxy overhead (with xss):", fmt(proxy_over_yes)],
        ["xss overhead (direct):", fmt(xss_over_direct)],
        ["xss overhead (proxy):", fmt(xss_over_proxy)],
    ]
    w0 = max(len(r[0]) for r in over_rows)
    for label, val in over_rows:
        print(label.ljust(w0), val)

    # If you want a single-line CSV to paste elsewhere:
    # print("\nCSV: Network,xss,n,avg_ms,median_ms,p95_ms,min_ms,max_ms")
    # for r in rows:
    #     print(",".join(map(str, [r[0], r[1], r[2], fmt(r[3]), fmt(r[4]), fmt(r[5]), fmt(r[6]), fmt(r[7])])))

if __name__ == "__main__":
    main()

