#!/usr/bin/env python3
"""
Netlas Hunter v8.0
- --test           : شغّل query واحدة بس للتجربة
- Streaming save   : بيكتب كل record فوراً على الـ disk
- Company file     : ملف أسماء شركات → ASNs → IPs
- Checkpoint       : استكمال من آخر نقطة
- Retry            : retry تلقائي عند فشل الشبكة
"""

import argparse
import csv
import json
import sys
import time
import signal
from datetime import datetime, timezone
from pathlib import Path

try:
    import netlas
except ImportError:
    print("[!] Run: pip install netlas")
    sys.exit(1)

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
OUTPUT_ROOT     = Path("netlas_results")
CHECKPOINT_FILE = Path("netlas_checkpoint.json")
SAVE_EVERY      = 50      # اكتب على الـ disk كل X records
MAX_RETRIES     = 5
RETRY_WAIT      = 10
SLEEP_BETWEEN   = 2.0

STRATEGIES = {
    "port_2087": [
        "port:2087",
        "port:2087 AND protocol:http",
        "port:2087 AND protocol:https",
        'port:2087 AND http.title:"WHM"',
        'port:2087 AND http.title:"WebHost Manager"',
        'port:2087 AND http.title:"cPanel"',
        'port:2087 AND http.body:"WHM"',
        'port:2087 AND http.body:"WebHost Manager"',
        "port:2087 AND cve.name:*",
        "port:2087 AND tag:cpanel",
        "port:2087 AND certificate.subject.common_name:*",
        'port:2087 AND http.software:"cPanel"',
        'port:2087 AND http.software:"Apache"',
        'port:2087 AND http.software:"LiteSpeed"',
        "port:2087 AND http.status_code:200",
        "port:2087 AND http.status_code:401",
        "port:2087 AND http.status_code:403",
    ],
    "port_2083": [
        "port:2083",
        "port:2083 AND protocol:http",
        "port:2083 AND protocol:https",
        'port:2083 AND http.title:"cPanel"',
        'port:2083 AND http.title:"Login"',
        'port:2083 AND http.body:"cPanel"',
        'port:2083 AND http.body:"Login to cPanel"',
        "port:2083 AND cve.name:*",
        "port:2083 AND tag:cpanel",
        "port:2083 AND certificate.subject.common_name:*",
        "port:2083 AND certificate.issuer.organization:*",
        'port:2083 AND http.software:"cPanel"',
        "port:2083 AND http.status_code:200",
        "port:2083 AND http.status_code:401",
        "port:2083 AND http.status_code:403",
    ],
}

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def sanitize(s):
    for ch in [':', ' ', '/', '\\', '*', '?', '"', '<', '>', "'", '(', ')']:
        s = s.replace(ch, '_')
    return s[:60]

def sep(title=""):
    print(f"\n{'═'*60}")
    if title:
        print(f"  ▶ {title}")
        print(f"{'═'*60}")

def create_session_dir(label=""):
    ts  = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    tag = f"_{sanitize(label)}" if label else ""
    d   = OUTPUT_ROOT / f"session_{ts}{tag}"
    d.mkdir(parents=True, exist_ok=True)
    return d

# ─────────────────────────────────────────────
# STREAMING WRITER
# بيكتب كل record فوراً على الـ disk
# ─────────────────────────────────────────────
class StreamWriter:
    CSV_FIELDS = ["ip","port","protocol","cves","asn","country",
                  "city","org","http_title","http_status","banner","source"]

    def __init__(self, session_dir, name):
        self.name      = sanitize(name)
        self.base      = session_dir / self.name
        self.count     = 0
        self.seen_ips  = set()
        self._buf      = []

        # CSV — فتح مرة واحدة وفضل مفتوح
        self._cf = open(f"{self.base}.csv", "w", newline="", encoding="utf-8")
        self._cw = csv.DictWriter(self._cf, fieldnames=self.CSV_FIELDS,
                                  extrasaction="ignore")
        self._cw.writeheader()
        self._cf.flush()

        # IPs — فتح مرة واحدة وفضل مفتوح
        self._ipf = open(f"{self.base}_ips.txt", "w", encoding="utf-8")

    def write(self, item):
        d    = item.get("data", {})
        ip   = d.get("ip", "")
        cves = d.get("cve", [])

        # ── CSV: اكتب فوراً ──
        self._cw.writerow({
            "ip":          ip,
            "port":        d.get("port", ""),
            "protocol":    d.get("protocol", ""),
            "cves":        ", ".join(c.get("name","") for c in cves) if isinstance(cves, list) else "",
            "asn":         d.get("autonomous_system", {}).get("number", "")
                           or d.get("asn", "")
                           or d.get("ip_whois", {}).get("asn", ""),
            "country":     d.get("geo", {}).get("country_iso_code", ""),
            "city":        d.get("geo", {}).get("city", ""),
            "org":         d.get("org", "")
                           or d.get("autonomous_system", {}).get("organization", ""),
            "http_title":  d.get("http", {}).get("title", ""),
            "http_status": d.get("http", {}).get("status_code", ""),
            "banner":      str(d.get("banner", ""))[:300].replace("\n", " "),
            "source":      item.get("source", ""),
        })

        # ── IP: اكتب فوراً لو جديد ──
        if ip and ip not in self.seen_ips:
            self.seen_ips.add(ip)
            self._ipf.write(ip + "\n")
            self._ipf.flush()          # flush فوري

        self._buf.append(item)
        self.count += 1

        # ── Flush كل SAVE_EVERY ──
        if self.count % SAVE_EVERY == 0:
            self._cf.flush()
            self._save_json()
            print(f"    💾 {self.count:,} records on disk …", end="\r", flush=True)

    def _save_json(self):
        with open(f"{self.base}.json", "w", encoding="utf-8") as f:
            json.dump(self._buf, f, indent=2, default=str)

    def close(self):
        self._cf.flush()
        self._cf.close()
        self._ipf.flush()
        self._ipf.close()
        self._save_json()
        print(f"\n    [✔] {self.name}: {self.count:,} records | "
              f"{len(self.seen_ips):,} unique IPs")


# ─────────────────────────────────────────────
# MASTER WRITER — all_results.*
# ─────────────────────────────────────────────
class MasterWriter(StreamWriter):
    def __init__(self, session_dir):
        super().__init__(session_dir, "all_results")
        # override paths to use flat names
        self.base  = session_dir / "all_results"
        self._cf   = open(session_dir / "all_results.csv", "w",
                          newline="", encoding="utf-8")
        self._cw   = csv.DictWriter(self._cf, fieldnames=self.CSV_FIELDS,
                                    extrasaction="ignore")
        self._cw.writeheader()
        self._cf.flush()
        self._ipf  = open(session_dir / "ips_only.txt", "w", encoding="utf-8")

    def close(self):
        self._cf.flush()
        self._cf.close()
        self._ipf.flush()
        self._ipf.close()
        self._save_json()
        print(f"\n[✔] MASTER: {self.count:,} total records | "
              f"{len(self.seen_ips):,} unique IPs")


# ─────────────────────────────────────────────
# CHECKPOINT
# ─────────────────────────────────────────────
class Checkpoint:
    def __init__(self, path=CHECKPOINT_FILE):
        self.path = Path(path)
        self.data = {
            "version":           "8.0",
            "started_at":        utcnow(),
            "last_updated":      utcnow(),
            "session_dir":       "",
            "completed_queries": [],
            "seen_keys":         [],
            "total_records":     0,
            "status":            "running",
        }

    def load(self):
        if not self.path.exists():
            return False
        try:
            saved = json.loads(self.path.read_text())
            if saved.get("status") == "done":
                return False
            self.data = saved
            print(f"\n{'='*60}")
            print(f"  ♻️  RESUME — session ناقصة!")
            print(f"  Started : {self.data.get('started_at','?')}")
            print(f"  Done    : {len(self.data['completed_queries'])} queries")
            print(f"  Records : {self.data['total_records']:,}")
            print(f"{'='*60}\n")
            return True
        except Exception as e:
            print(f"[!] Checkpoint load error: {e}")
            return False

    def save(self):
        self.data["last_updated"] = utcnow()
        self.path.write_text(json.dumps(self.data, indent=2, default=str))

    def mark_done(self):
        self.data["status"] = "done"
        self.save()

    def mark_query_complete(self, query, n=0):
        if query not in self.data["completed_queries"]:
            self.data["completed_queries"].append(query)
        self.data["total_records"] += n
        self.save()

    def is_done(self, query):
        return query in self.data["completed_queries"]

    def set_session_dir(self, p):
        self.data["session_dir"] = str(p)
        self.save()

    def set_seen_keys(self, keys):
        self.data["seen_keys"] = list(keys)
        self.save()

    def get_seen_keys(self):
        return set(self.data.get("seen_keys", []))

    def clear(self):
        if self.path.exists():
            self.path.unlink()


# ─────────────────────────────────────────────
# NETWORK HELPERS
# ─────────────────────────────────────────────
def is_network_error(e):
    s = str(e)
    return any(x in s for x in ["resolve", "timed out", "ConnectionPool",
                                  "RemoteDisconnected", "ConnectionError"])

def get_count(client, query, datatype="responses"):
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = client.count(query=query, datatype=datatype)
            return int(r.get("total", r.get("count", -1)))
        except Exception as e:
            if is_network_error(e):
                print(f"    [!] Network ({attempt}/{MAX_RETRIES}) — wait {RETRY_WAIT}s …")
                time.sleep(RETRY_WAIT)
            else:
                return -1
    return -1


# ─────────────────────────────────────────────
# CORE FETCH — Streaming
# ─────────────────────────────────────────────
def stream_fetch(client, query, label, seen_keys,
                 query_writer, master_writer, datatype="responses"):
    """
    بيسحب النتايج ويكتبهم فوراً على الـ disk
    لو download_all فشلت — بيعمل pagination يدوي
    """
    new_count = 0

    def process_item(item):
        nonlocal new_count
        try:
            if isinstance(item, str):
                item = json.loads(item)
            data  = item.get("data", item)
            entry = {"source": label, "data": data}
            ip    = data.get("ip", "")
            prt   = str(data.get("port", ""))
            key   = f"{ip}:{prt}"
            if ip and key not in seen_keys:
                seen_keys.add(key)
                query_writer.write(entry)
                master_writer.write(entry)
                new_count += 1
        except Exception:
            pass

    # ── جرب download_all ─────────────────────
    dl_success = False
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            for item in client.download_all(query=query, datatype=datatype):
                process_item(item)
            dl_success = True
            break
        except Exception as e:
            if is_network_error(e):
                print(f"\n    [!] Network ({attempt}/{MAX_RETRIES}) — wait {RETRY_WAIT}s …")
                time.sleep(RETRY_WAIT)
                new_count = 0
            else:
                break

    # ── Fallback: pagination لو download_all رجعت 0 ─
    if not dl_success or new_count == 0:
        total = get_count(client, query, datatype)
        if total and total > 0:
            print(f"    [~] Pagination fallback ({total:,}) …")
            start = 0
            while start < total:
                page_ok = False
                for attempt in range(1, MAX_RETRIES + 1):
                    try:
                        resp  = client.query(query=query, datatype=datatype,
                                             indices=start, size=50)
                        items = resp.get("items", [])
                        if not items:
                            start = total  # خلص
                            page_ok = True
                            break
                        for item in items:
                            process_item(item)
                        start  += len(items)
                        page_ok = True
                        time.sleep(0.5)
                        break
                    except Exception as e:
                        if is_network_error(e):
                            print(f"\n    [!] Network ({attempt}/{MAX_RETRIES}) — wait {RETRY_WAIT}s …")
                            time.sleep(RETRY_WAIT)
                        else:
                            start = total
                            page_ok = True
                            break
                if not page_ok:
                    break

    print(f"    ↳ +{new_count:,} new records saved ✓")
    return new_count


# ─────────────────────────────────────────────
# QUERY RUNNER
# ─────────────────────────────────────────────
def run_query(client, query, seen_keys, session_dir,
              master_writer, cp, group_writer=None, test_mode=False):

    if cp.is_done(query):
        print(f"  [↩] SKIP: {query[:65]}")
        return 0

    available = get_count(client, query)
    print(f"\n  Query     : {query}")
    print(f"  Available : {available:,}" if available >= 0 else "  Available : ?")

    if available == 0:
        print("  → Skip (0 results)")
        cp.mark_query_complete(query, 0)
        return 0

    # لو test mode — بس اطبع الـ count ومتسحبش
    if test_mode:
        print(f"  [TEST] ✅ Query شغالة — {available:,} results متاحة")
        cp.mark_query_complete(query, 0)
        return available

    q_writer = group_writer or StreamWriter(session_dir, sanitize(query))
    new = stream_fetch(client, query, query, seen_keys, q_writer, master_writer)

    if group_writer is None:
        q_writer.close()

    cp.set_seen_keys(seen_keys)
    cp.mark_query_complete(query, new)
    time.sleep(SLEEP_BETWEEN)
    return new


# ─────────────────────────────────────────────
# PORT GROUP
# ─────────────────────────────────────────────
def run_port_group(client, group_name, queries, seen_keys,
                   session_dir, master_writer, cp, test_mode=False):
    sep(f"PORT GROUP: {group_name}  ({len(queries)} queries)")

    # لو test mode — شغّل query واحدة بس
    if test_mode:
        q = queries[0]
        print(f"\n  [TEST MODE] شغّل query واحدة بس:")
        run_query(client, q, seen_keys, session_dir,
                  master_writer, cp, test_mode=True)
        print(f"\n  [TEST] ✅ شغال! شغّل من غير --test عشان تجيب كل النتايج")
        return []

    group_writer = StreamWriter(session_dir, group_name)
    for i, query in enumerate(queries, 1):
        print(f"\n  [{i:02d}/{len(queries):02d}]", end=" ")
        run_query(client, query, seen_keys, session_dir,
                  master_writer, cp, group_writer)
    group_writer.close()


# ─────────────────────────────────────────────
# ASN HARVEST
# ─────────────────────────────────────────────
def harvest_asn(client, asn, port, seen_keys,
                session_dir, master_writer, cp, test_mode=False):
    asn_clean = str(asn).upper().replace("AS", "")
    asn_str   = f"AS{asn_clean}"
    label     = f"{asn_str}_port{port}" if port else f"{asn_str}_all"

    # جرب صيغ مختلفة للـ ASN field
    if port:
        variants = [
            f"port:{port} AND autonomous_system.number:{asn_clean}",
            f"port:{port} AND asn:{asn_clean}",
            f"port:{port} AND ip_whois.asn:AS{asn_clean}",
        ]
    else:
        variants = [
            f"autonomous_system.number:{asn_clean}",
            f"asn:{asn_clean}",
            f"ip_whois.asn:AS{asn_clean}",
        ]

    sep(f"ASN: {asn_str}" + (f"  Port:{port}" if port else "  ALL IPs"))

    writer = StreamWriter(session_dir, label)
    found  = False
    for query in variants:
        count = get_count(client, query)
        print(f"  Testing : {query}")
        print(f"  Count   : {count:,}" if count >= 0 else "  Count   : ?")

        if count == 0:
            print(f"  → 0, trying next …")
            continue

        if test_mode:
            print(f"  [TEST] ✅ Query شغالة — {count:,} متاحة")
            found = True
            break

        run_query(client, query, seen_keys, session_dir,
                  master_writer, cp, writer)
        found = True
        break

    if not found:
        print(f"  [!] No results for {asn_str}")

    writer.close()


# ─────────────────────────────────────────────
# COMPANY → ASN → IPs
# ─────────────────────────────────────────────
def process_company(client, company, port, seen_keys,
                    session_dir, master_writer, cp, test_mode=False):
    sep(f"COMPANY: {company}")
    asn_set = set()

    # صيغ البحث عن الشركة
    company_queries = [
        f'autonomous_system.organization:"{company}"',
        f'ip_whois.org:"{company}"',
        f'org:"{company}"',
    ]

    print(f"  [1/2] البحث عن ASNs لـ: {company} …")

    for q in company_queries:
        count = get_count(client, q)
        print(f"\n  Query   : {q}")
        print(f"  Count   : {count:,}" if count >= 0 else "  Count   : ?")

        if count == 0:
            continue

        if test_mode:
            print(f"  [TEST] ✅ Query شغالة — {count:,} متاحة")
            return

        # اسحب واستخرج الـ ASN numbers
        tmp_writer = StreamWriter(session_dir, f"co_{sanitize(company)}_lookup")
        run_query(client, q, seen_keys, session_dir,
                  master_writer, cp, tmp_writer)

        for item in tmp_writer._buf:
            d = item.get("data", {})
            for val in [
                d.get("autonomous_system", {}).get("number"),
                d.get("asn"),
                d.get("ip_whois", {}).get("asn"),
            ]:
                if val:
                    clean = str(val).upper().replace("AS", "").strip()
                    if clean.isdigit():
                        asn_set.add(clean)

        tmp_writer.close()

        if asn_set:
            break

    asns = sorted(asn_set)
    if not asns:
        print(f"\n  [!] مش لاقي ASNs لـ '{company}' — جرب اسم أقصر أو مختلف")
        return

    print(f"\n  ✅ [1/2] ASNs لقاها لـ {company}: {len(asns)}")
    for a in asns:
        print(f"     AS{a}")

    # احفظ قائمة الـ ASNs
    asn_file = session_dir / f"asns_{sanitize(company)}.txt"
    asn_file.write_text(
        f"# ASNs for: {company}\n" + "\n".join(f"AS{a}" for a in asns)
    )
    print(f"  [✔] → {asn_file.name}")

    # [2/2] اسحب IPs من كل ASN
    print(f"\n  [2/2] سحب IPs من {len(asns)} ASN …")
    for i, asn in enumerate(asns, 1):
        print(f"\n  [{i}/{len(asns)}] AS{asn}")
        harvest_asn(client, asn, port, seen_keys,
                    session_dir, master_writer, cp, test_mode)


# ─────────────────────────────────────────────
# BANNER / STATS
# ─────────────────────────────────────────────
def print_banner():
    print(r"""
  ███╗   ██╗███████╗████████╗██╗      █████╗ ███████╗
  ████╗  ██║██╔════╝╚══██╔══╝██║     ██╔══██╗██╔════╝
  ██╔██╗ ██║█████╗     ██║   ██║     ███████║███████╗
  ██║╚██╗██║██╔══╝     ██║   ██║     ██╔══██║╚════██║
  ██║ ╚████║███████╗   ██║   ███████╗██║  ██║███████║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝
     Hunter v8.0 ★ Test Mode ★ Streaming Save
    """)

def print_stats(master, session_dir, cp):
    sep("FINAL SUMMARY")
    print(f"  ✅ TOTAL RECORDS  : {master.count:,}")
    print(f"  ✅ UNIQUE IPs     : {len(master.seen_ips):,}")
    print(f"  ✅ QUERIES DONE   : {len(cp.data['completed_queries'])}")
    print(f"  ✅ FINISHED AT    : {utcnow()}")
    print(f"\n  📁 {session_dir.resolve()}\n")
    cp.mark_done()


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Netlas Hunter v8.0")
    parser.add_argument("-k","--api-key",         required=True)
    parser.add_argument("--no-2087",              action="store_true")
    parser.add_argument("--no-2083",              action="store_true")
    parser.add_argument("--ports",                nargs="+", type=int)
    parser.add_argument("--asn-company",          metavar="NAME")
    parser.add_argument("--asn-company-file",     metavar="FILE",
                        help="ملف أسماء شركات — سطر لكل شركة")
    parser.add_argument("--asn",                  nargs="+", metavar="ASN")
    parser.add_argument("--asn-file",             metavar="FILE")
    parser.add_argument("--asn-port",             type=int)
    parser.add_argument("--cve",                  nargs="+", metavar="CVE_ID")
    parser.add_argument("--query",                help="Raw Netlas query")
    parser.add_argument("--only-asn",             action="store_true")
    parser.add_argument("--only-ports",           action="store_true")
    parser.add_argument("--test",                 action="store_true",
                        help="شغّل query واحدة بس للتجربة — مش بيسحب داتا")
    parser.add_argument("--reset",                action="store_true",
                        help="امسح checkpoint وابدأ من الأول")
    args = parser.parse_args()

    # ── Checkpoint ────────────────────────────
    cp = Checkpoint()
    if args.reset:
        cp.clear()
        print("[+] Checkpoint cleared")

    resumed = cp.load()

    if resumed and cp.data.get("session_dir"):
        session_dir = Path(cp.data["session_dir"])
        session_dir.mkdir(parents=True, exist_ok=True)
        print(f"[+] Resuming: {session_dir}")
    else:
        session_dir = create_session_dir("test" if args.test else "")
        cp.set_session_dir(session_dir)
        print(f"[+] Session: {session_dir}")

    client        = netlas.Netlas(api_key=args.api_key)
    seen_keys     = cp.get_seen_keys()
    master_writer = MasterWriter(session_dir)

    # ── Signal handler ────────────────────────
    def graceful_exit(sig, frame):
        print(f"\n\n  ⚠️  Interrupted!")
        try:
            master_writer._cf.flush()
            master_writer._ipf.flush()
        except Exception:
            pass
        cp.set_seen_keys(seen_keys)
        cp.save()
        print(f"  ✅ محفوظ — شغّل تاني وهيكمل من نفس النقطة")
        sys.exit(0)

    signal.signal(signal.SIGINT,  graceful_exit)
    signal.signal(signal.SIGTERM, graceful_exit)

    # ── Build lists ───────────────────────────
    asn_list   = list(args.asn or [])
    if args.asn_file:
        try:
            for line in Path(args.asn_file).read_text().splitlines():
                line = line.split("#")[0].strip()
                if line:
                    asn_list.append(line)
            print(f"[+] {len(asn_list)} ASNs from {args.asn_file}")
        except FileNotFoundError:
            print(f"[!] ASN file not found: {args.asn_file}")

    companies = []
    if args.asn_company:
        companies.append(args.asn_company)
    if args.asn_company_file:
        try:
            for line in Path(args.asn_company_file).read_text(encoding="utf-8").splitlines():
                line = line.split("#")[0].strip()
                if line:
                    companies.append(line)
            print(f"[+] {len(companies)} companies from {args.asn_company_file}")
        except FileNotFoundError:
            print(f"[!] Company file not found: {args.asn_company_file}")

    # ── Auto-detect mode ──────────────────────
    asn_mode        = bool(companies or asn_list)
    run_port_search = (not args.only_asn) and (not asn_mode or args.only_ports)

    print(f"\n  Mode      : {'TEST 🧪' if args.test else ('RESUME ♻️' if resumed else 'NEW 🆕')}")
    print(f"  Save every: {SAVE_EVERY} records")
    print(f"  Retries   : {MAX_RETRIES}x / {RETRY_WAIT}s")
    if args.test:
        print(f"  [TEST] بيشغّل query واحدة بس — مش هيسحب داتا")

    # ══════════════════════════════════════════
    # PORT MODE
    # ══════════════════════════════════════════
    if run_port_search:
        if not args.no_2087:
            run_port_group(client, "port_2087", STRATEGIES["port_2087"],
                           seen_keys, session_dir, master_writer, cp, args.test)
        if not args.no_2083:
            run_port_group(client, "port_2083", STRATEGIES["port_2083"],
                           seen_keys, session_dir, master_writer, cp, args.test)
        if args.ports:
            for port in args.ports:
                run_port_group(client, f"port_{port}", [
                    f"port:{port}", f"port:{port} AND protocol:http",
                    f"port:{port} AND protocol:https",
                    f"port:{port} AND cve.name:*",
                ], seen_keys, session_dir, master_writer, cp, args.test)

    # ══════════════════════════════════════════
    # COMPANY MODE
    # ══════════════════════════════════════════
    if not args.only_ports:
        if companies:
            print(f"\n  [*] {len(companies)} companies to process …")
            for i, company in enumerate(companies, 1):
                print(f"\n  [Company {i}/{len(companies)}] {company}")
                process_company(client, company, args.asn_port,
                                seen_keys, session_dir, master_writer, cp, args.test)

        for asn in asn_list:
            harvest_asn(client, asn, args.asn_port,
                        seen_keys, session_dir, master_writer, cp, args.test)

    # ══════════════════════════════════════════
    # CVE MODE
    # ══════════════════════════════════════════
    if args.cve:
        sep(f"CVE  ({len(args.cve)} CVEs)")
        cve_writer = StreamWriter(session_dir, "cve_results")
        for cve_id in args.cve:
            print(f"\n  CVE: {cve_id}")
            run_query(client, f"cve.name:{cve_id.upper()}",
                      seen_keys, session_dir, master_writer, cp,
                      cve_writer, test_mode=args.test)
        cve_writer.close()

    # ══════════════════════════════════════════
    # CUSTOM QUERY
    # ══════════════════════════════════════════
    if args.query:
        sep(f"CUSTOM: {args.query}")
        run_query(client, args.query, seen_keys, session_dir,
                  master_writer, cp, test_mode=args.test)

    master_writer.close()
    if not args.test:
        print_stats(master_writer, session_dir, cp)
    else:
        print(f"\n  ✅ TEST خلص — كل الـ queries شغالة!")
        print(f"  شغّل من غير --test عشان تسحب الداتا الحقيقية\n")
        cp.mark_done()


if __name__ == "__main__":
    main()