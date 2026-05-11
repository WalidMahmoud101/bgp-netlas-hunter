#!/usr/bin/env python3
"""
BGP Hunter v4.0 — Playwright Browser Scraper
بيفتح Chrome الحقيقي بـ Playwright ويسحب ASNs من bgp.he.net

Requirements:
  pip install playwright beautifulsoup4
  playwright install chromium

Usage:
  python3 bgp_hunter.py --company "Webafrica FTTH - CPT"
  python3 bgp_hunter.py --company-file companies.txt
  python3 bgp_hunter.py --asn AS37087
  python3 bgp_hunter.py --company "Hetzner" --fetch-prefixes
  python3 bgp_hunter.py --company-file companies.txt --netlas-key YOUR_KEY --netlas-port 2087
"""

import argparse
import json
import sys
import time
import asyncio
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

# ── Check dependencies ────────────────────────
try:
    from playwright.async_api import async_playwright, TimeoutError as PWTimeout
except ImportError:
    print("[!] Install Playwright:")
    print("    pip install playwright")
    print("    playwright install chromium")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] Install BeautifulSoup:")
    print("    pip install beautifulsoup4")
    sys.exit(1)

OUTPUT_DIR = Path("bgp_results")
BASE_URL   = "https://bgp.he.net"
SLEEP      = 1.5   # بين كل request

# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────
def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def sanitize(s):
    for ch in [':', ' ', '/', '\\', '*', '?', '"', '<', '>', "'", '(', ')', '+', '-']:
        s = s.replace(ch, '_')
    return s[:60].strip('_')

def sep(title=""):
    print(f"\n{'═'*58}")
    if title:
        print(f"  ▶ {title}")
        print(f"{'═'*58}")

def print_banner():
    print(r"""
  ██████╗  ██████╗ ██████╗     ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██╔══██╗██╔════╝ ██╔══██╗    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ██████╔╝██║  ███╗██████╔╝    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██╔══██╗██║   ██║██╔═══╝     ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ██████╔╝╚██████╔╝██║         ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═════╝  ╚═════╝ ╚═╝         ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
     v4.0 — Playwright Browser Scraper (bgp.he.net)
    """)

# ─────────────────────────────────────────────
# PARSE HTML HELPERS
# ─────────────────────────────────────────────
def parse_search_results(html: str) -> list:
    """استخرج ASNs من صفحة البحث"""
    soup    = BeautifulSoup(html, "html.parser")
    results = []

    table = soup.find("table", id="searchresults")
    if not table:
        # جرب أي table
        for t in soup.find_all("table"):
            if t.find("td"):
                table = t
                break

    if not table:
        return []

    for row in table.find_all("tr")[1:]:
        cols = row.find_all("td")
        if len(cols) < 2:
            continue

        asn_link = cols[0].find("a")
        if not asn_link:
            continue

        asn_text = asn_link.text.strip().replace("AS", "")
        if not asn_text.isdigit():
            continue

        name        = cols[1].text.strip() if len(cols) > 1 else ""
        prefixes_v4 = cols[2].text.strip() if len(cols) > 2 else "?"
        prefixes_v6 = cols[3].text.strip() if len(cols) > 3 else "?"

        country = ""
        flag = row.find("img")
        if flag:
            country = flag.get("alt", "") or flag.get("title", "")

        results.append({
            "asn":         asn_text,
            "name":        name,
            "prefixes_v4": prefixes_v4,
            "prefixes_v6": prefixes_v6,
            "country":     country,
        })

    return results


def parse_prefixes(html: str) -> list:
    """استخرج IPv4 prefixes من صفحة ASN"""
    soup     = BeautifulSoup(html, "html.parser")
    prefixes = []

    table = soup.find("table", id="table_prefixes4")
    if not table:
        return []

    for row in table.find_all("tr")[1:]:
        cols = row.find_all("td")
        if not cols:
            continue
        link = cols[0].find("a")
        if link:
            prefix = link.text.strip()
            if "/" in prefix and ":" not in prefix:
                prefixes.append(prefix)

    return prefixes


# ─────────────────────────────────────────────
# PLAYWRIGHT BROWSER
# ─────────────────────────────────────────────
async def create_browser(playwright, headless=True):
    """شغّل Chromium بإعدادات تتخطى الـ bot detection"""
    browser = await playwright.chromium.launch(
        headless=headless,
        args=[
            "--no-sandbox",
            "--disable-blink-features=AutomationControlled",
        ]
    )
    context = await browser.new_context(
        viewport={"width": 1920, "height": 1080},
        user_agent=(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        locale="en-US",
        timezone_id="America/New_York",
        extra_http_headers={
            "Accept-Language": "en-US,en;q=0.9",
        }
    )
    # تخطى الـ webdriver detection
    await context.add_init_script("""
        Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
        Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3]});
    """)
    page = await context.new_page()
    return browser, context, page


async def safe_goto(page, url: str, retries=3) -> bool:
    """افتح الـ URL مع retry"""
    for attempt in range(1, retries + 1):
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=20000)
            await page.wait_for_timeout(1500)
            return True
        except PWTimeout:
            print(f"    [!] Timeout (attempt {attempt}/{retries})")
            if attempt < retries:
                await page.wait_for_timeout(2000)
        except Exception as e:
            print(f"    [!] Error: {e}")
            if attempt < retries:
                await page.wait_for_timeout(2000)
    return False


# ─────────────────────────────────────────────
# SEARCH
# ─────────────────────────────────────────────
async def search_asn(page, company: str) -> list:
    """ابحث عن ASNs بتاعة شركة"""
    encoded = urllib.parse.quote_plus(company)
    url     = f"{BASE_URL}/search?search%5Bsearch%5D={encoded}&commit=Search"

    print(f"  Searching : {company}")

    ok = await safe_goto(page, url)
    if not ok:
        print(f"  [!] Failed to load page")
        return []

    html    = await page.content()
    results = parse_search_results(html)

    if results:
        print(f"  Found     : {len(results)} ASNs")
        for r in results:
            print(f"    AS{r['asn']:<10} | {r['name'][:45]:<45} | "
                  f"v4:{r['prefixes_v4']:<6} | {r['country']}")
    else:
        print(f"  [!] No ASNs found for '{company}'")

    return results


async def get_prefixes(page, asn: str) -> list:
    """جيب IPv4 prefixes من ASN"""
    asn_clean = str(asn).replace("AS", "")
    url       = f"{BASE_URL}/AS{asn_clean}#_prefixes"

    print(f"\n  Prefixes  : AS{asn_clean} …")
    ok = await safe_goto(page, url)
    if not ok:
        return []

    # انتظر تتحمل الـ prefixes table
    try:
        await page.wait_for_selector("#table_prefixes4", timeout=8000)
    except PWTimeout:
        pass

    html     = await page.content()
    prefixes = parse_prefixes(html)

    print(f"  Found     : {len(prefixes)} IPv4 prefixes")
    for p in prefixes[:10]:
        print(f"    {p}")
    if len(prefixes) > 10:
        print(f"    … و {len(prefixes)-10} تانيين")

    return prefixes


# ─────────────────────────────────────────────
# SAVE
# ─────────────────────────────────────────────
def save_company(company, asns, prefixes_map, session_dir):
    safe = sanitize(company)

    # JSON
    (session_dir / f"{safe}.json").write_text(
        json.dumps({
            "company":  company,
            "date":     utcnow(),
            "asns":     asns,
            "prefixes": prefixes_map,
        }, indent=2, default=str),
        encoding="utf-8"
    )

    # ASNs TXT
    asn_txt = session_dir / f"{safe}_asns.txt"
    with open(asn_txt, "w", encoding="utf-8") as f:
        f.write(f"# ASNs for: {company}\n")
        f.write(f"# Date: {utcnow()}\n\n")
        for r in asns:
            f.write(f"AS{r['asn']}   # {r.get('name','')}\n")
    print(f"  [✔] ASNs     → {asn_txt.name}")

    # Prefixes TXT
    if prefixes_map:
        pfx_txt = session_dir / f"{safe}_prefixes.txt"
        with open(pfx_txt, "w", encoding="utf-8") as f:
            f.write(f"# Prefixes for: {company}\n\n")
            for asn_num, pfxs in prefixes_map.items():
                f.write(f"# AS{asn_num}\n")
                for p in pfxs:
                    f.write(p + "\n")
                f.write("\n")
        print(f"  [✔] Prefixes → {pfx_txt.name}")

    return asn_txt


def save_master(all_data, session_dir):
    path = session_dir / "all_asns.txt"
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"# All ASNs — {utcnow()}\n\n")
        for company, asns in all_data.items():
            f.write(f"# ── {company} ──\n")
            for r in asns:
                f.write(f"AS{r['asn']}   # {r.get('name','')}\n")
            f.write("\n")
    total = sum(len(v) for v in all_data.values())
    print(f"\n  [✔] Master → {path.name}  ({total} ASNs total)")
    return path


# ─────────────────────────────────────────────
# MAIN ASYNC
# ─────────────────────────────────────────────
async def run(args, companies, session_dir):
    async with async_playwright() as pw:
        browser, context, page = await create_browser(
            pw, headless=not args.show_browser
        )
        print(f"[✔] Chromium ready")

        try:
            # ── Single ASN ────────────────────
            if args.asn:
                sep(f"ASN: {args.asn}")
                prefixes = await get_prefixes(page, args.asn)
                if prefixes:
                    asn_clean = args.asn.replace("AS","")
                    path = session_dir / f"AS{asn_clean}_prefixes.txt"
                    path.write_text("\n".join(prefixes))
                    print(f"\n  [✔] Saved → {path}")
                return

            # ── Companies ─────────────────────
            all_data = {}

            for i, company in enumerate(companies, 1):
                sep(f"[{i}/{len(companies)}] {company}")

                asns = await search_asn(page, company)
                if not asns:
                    await asyncio.sleep(SLEEP)
                    continue

                # Prefixes
                prefixes_map = {}
                if args.fetch_prefixes:
                    for r in asns:
                        pfxs = await get_prefixes(page, r["asn"])
                        if pfxs:
                            prefixes_map[r["asn"]] = pfxs
                        await asyncio.sleep(SLEEP)

                all_data[company] = asns
                save_company(company, asns, prefixes_map, session_dir)
                await asyncio.sleep(SLEEP)

            # ── Master + Summary ──────────────
            if not all_data:
                print("\n[!] No ASNs found for any company")
                return

            master = save_master(all_data, session_dir)
            total  = sum(len(v) for v in all_data.values())

            sep("SUMMARY")
            print(f"  ✅ Companies : {len(all_data)}/{len(companies)}")
            print(f"  ✅ Total ASNs: {total}")
            print(f"  ✅ Output    : {session_dir.resolve()}")

            # ── Auto netlas ───────────────────
            if args.netlas_key:
                import subprocess
                print(f"\n  [→] Running netlas_hunter …")
                cmd = [
                    sys.executable, "netlas_hunter.py",
                    "-k", args.netlas_key,
                    "--asn-file", str(master),
                    "--asn-port", str(args.netlas_port),
                ]
                print(f"  CMD: {' '.join(cmd)}\n")
                subprocess.run(cmd)
            else:
                print(f"\n  [→] Next step:")
                print(f"      python3 netlas_hunter.py -k YOUR_KEY \\")
                print(f"        --asn-file {master} \\")
                print(f"        --asn-port {args.netlas_port}")

        finally:
            await context.close()
            await browser.close()
            print(f"\n[✔] Browser closed")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="BGP Hunter v4 — Playwright scraper for bgp.he.net"
    )
    parser.add_argument("--company",        metavar="NAME")
    parser.add_argument("--company-file",   metavar="FILE")
    parser.add_argument("--asn",            metavar="ASN")
    parser.add_argument("--fetch-prefixes", action="store_true",
                        help="جيب IPv4 prefixes لكل ASN")
    parser.add_argument("--show-browser",   action="store_true",
                        help="اعرض المتصفح بدل headless")
    parser.add_argument("--netlas-key",     metavar="KEY")
    parser.add_argument("--netlas-port",    type=int, default=2087)
    args = parser.parse_args()

    if not any([args.company, args.company_file, args.asn]):
        parser.print_help()
        sys.exit(1)

    # ── Build company list ────────────────────
    companies = []
    if args.company:
        companies.append(args.company)
    if args.company_file:
        try:
            for line in Path(args.company_file).read_text(encoding="utf-8").splitlines():
                line = line.split("#")[0].strip()
                if line:
                    companies.append(line)
            print(f"[+] {len(companies)} companies loaded from {args.company_file}")
        except FileNotFoundError:
            print(f"[!] File not found: {args.company_file}")
            sys.exit(1)

    # ── Session dir ───────────────────────────
    OUTPUT_DIR.mkdir(exist_ok=True)
    ts          = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    session_dir = OUTPUT_DIR / f"session_{ts}"
    session_dir.mkdir()
    print(f"[+] Output : {session_dir.resolve()}")
    print(f"[+] Time   : {utcnow()}")

    asyncio.run(run(args, companies, session_dir))


if __name__ == "__main__":
    main()