#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analyza navstev AI crawlerov v access logoch (Apache/nginx combined format).

Pouzitie:
    python analyza_ai_botov.py <cesta_k_logu_alebo_adresaru> [dalsie cesty...]

Podporuje .log, .txt, .gz a adresare (rekurzivne).
Overuje pravost botov proti oficialnym IP rozsahom OpenAI/Anthropic/Google.
"""
import sys, os, re, gzip, glob, json, ipaddress, collections, csv
from datetime import datetime

IPS_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------- katalog botov
# kategoria: TRENING = zbiera data na trenovanie modelu
#            VYHLADAVANIE = buduje index pre AI vyhladavanie
#            ZIVY_FETCH = model si stiahol stranku na ziadost pouzivatela (uz JE v odpovedi!)
BOTS = [
    # vzor (regex, case-insensitive), nazov, firma, kategoria, subor s IP rozsahmi
    (r"GPTBot",                     "GPTBot",              "OpenAI",     "TRENING",      "ips_openai_gptbot.json"),
    (r"OAI-SearchBot",              "OAI-SearchBot",       "OpenAI",     "VYHLADAVANIE", "ips_openai_searchbot.json"),
    (r"ChatGPT-User",               "ChatGPT-User",        "OpenAI",     "ZIVY_FETCH",   "ips_openai_chatgpt_user.json"),
    (r"ClaudeBot",                  "ClaudeBot",           "Anthropic",  "TRENING",      "ips_anthropic.json"),
    (r"Claude-SearchBot",           "Claude-SearchBot",    "Anthropic",  "VYHLADAVANIE", "ips_anthropic.json"),
    (r"Claude-User",                "Claude-User",         "Anthropic",  "ZIVY_FETCH",   "ips_anthropic.json"),
    (r"anthropic-ai",               "anthropic-ai (old)",  "Anthropic",  "TRENING",      "ips_anthropic.json"),
    (r"Claude-Web",                 "Claude-Web (old)",    "Anthropic",  "TRENING",      "ips_anthropic.json"),
    (r"Google-CloudVertexBot",      "Google-CloudVertexBot","Google",    "TRENING",      "ips_google_special.json"),
    (r"GoogleOther",                "GoogleOther",         "Google",     "TRENING",      "ips_google_special.json"),
    (r"Google-Extended",            "Google-Extended",     "Google",     "TRENING",      None),
    (r"Googlebot",                  "Googlebot",           "Google",     "VYHLADAVANIE", "ips_google_googlebot.json"),
    (r"Google-InspectionTool",      "Google-InspectionTool","Google",    "ZIVY_FETCH",   "ips_google_user_triggered.json"),
    (r"CCBot",                      "CCBot (Common Crawl)","CommonCrawl","TRENING",      None),
    (r"PerplexityBot",              "PerplexityBot",       "Perplexity", "VYHLADAVANIE", None),
    (r"Perplexity-User",            "Perplexity-User",     "Perplexity", "ZIVY_FETCH",   None),
    (r"Bytespider",                 "Bytespider",          "ByteDance",  "TRENING",      None),
    (r"Amazonbot",                  "Amazonbot",           "Amazon",     "TRENING",      None),
    (r"Applebot-Extended",          "Applebot-Extended",   "Apple",      "TRENING",      None),
    (r"Applebot",                   "Applebot",            "Apple",      "VYHLADAVANIE", None),
    (r"meta-externalagent",         "meta-externalagent",  "Meta",       "TRENING",      None),
    (r"Meta-ExternalFetcher",       "Meta-ExternalFetcher","Meta",       "ZIVY_FETCH",   None),
    (r"FacebookBot",                "FacebookBot",         "Meta",       "TRENING",      None),
    (r"cohere-(?:ai|training)",     "cohere-ai",           "Cohere",     "TRENING",      None),
    (r"MistralAI-User",             "MistralAI-User",      "Mistral",    "ZIVY_FETCH",   None),
    (r"DuckAssistBot",              "DuckAssistBot",       "DuckDuckGo", "VYHLADAVANIE", None),
    (r"AI2Bot",                     "AI2Bot",              "AllenAI",    "TRENING",      None),
    (r"Diffbot",                    "Diffbot",             "Diffbot",    "TRENING",      None),
    (r"ImagesiftBot",               "ImagesiftBot",        "Imagesift",  "TRENING",      None),
    (r"Omgili",                     "Omgilibot",           "Webz.io",    "TRENING",      None),
    (r"YouBot",                     "YouBot",              "You.com",    "VYHLADAVANIE", None),
    (r"Timpibot",                   "Timpibot",            "Timpi",      "TRENING",      None),
    (r"TikTokSpider",               "TikTokSpider",        "ByteDance",  "TRENING",      None),
    (r"Bingbot",                    "Bingbot",             "Microsoft",  "VYHLADAVANIE", None),
]
COMPILED = [(re.compile(p, re.I), n, c, k, f) for p, n, c, k, f in BOTS]

# ---------------------------------------------------------------- IP overovanie
def load_prefixes():
    cache = {}
    for fn in glob.glob(os.path.join(IPS_DIR, "ips_*.json")):
        nets = []
        try:
            with open(fn, encoding="utf-8-sig") as fh:
                data = json.load(fh)
            for p in data.get("prefixes", []):
                cidr = p.get("ipv4Prefix") or p.get("ipv6Prefix")
                if cidr:
                    try:
                        nets.append(ipaddress.ip_network(cidr, strict=False))
                    except ValueError:
                        pass
        except Exception:
            pass
        cache[os.path.basename(fn)] = nets
    return cache

PREFIXES = load_prefixes()

def ip_patri(ip_str, subor):
    """Overi, ci IP patri do oficialnych rozsahov danej firmy."""
    if not subor or subor not in PREFIXES or not PREFIXES[subor]:
        return None  # nemame comparovat voci comu
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    for net in PREFIXES[subor]:
        if ip.version == net.version and ip in net:
            return True
    return False

# ---------------------------------------------------------------- parsovanie
LOG_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<cas>[^\]]+)\]\s+'
    r'"(?P<metoda>[A-Z]+)\s+(?P<cesta>\S*)[^"]*"\s+'
    r'(?P<status>\d{3})\s+(?P<bajty>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

def otvor(path):
    # utf-8-sig zahodi pripadny BOM - inak by sa prva IP v subore rozbila
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8-sig", errors="replace")
    return open(path, "r", encoding="utf-8-sig", errors="replace")

def zozbieraj_subory(cesty):
    subory = []
    for c in cesty:
        if os.path.isdir(c):
            for root, _, files in os.walk(c):
                for f in files:
                    if re.search(r"(access|log)", f, re.I) or f.endswith(".gz"):
                        subory.append(os.path.join(root, f))
        else:
            subory.extend(glob.glob(c) or [c])
    return [s for s in subory if os.path.isfile(s)]

def klasifikuj(ua):
    for rx, nazov, firma, kat, ipf in COMPILED:
        if rx.search(ua):
            return nazov, firma, kat, ipf
    return None

# ---------------------------------------------------------------- hlavna analyza
def main():
    if len(sys.argv) < 2:
        print(__doc__)
        print("CHYBA: zadajte cestu k access logu.")
        sys.exit(1)

    subory = zozbieraj_subory(sys.argv[1:])
    if not subory:
        print("CHYBA: nenasiel som ziadny log subor.")
        sys.exit(1)

    print("=" * 78)
    print("ANALYZA NAVSTEV AI CRAWLEROV")
    print("=" * 78)
    print(f"Spracuvam {len(subory)} suborov:")
    for s in subory[:20]:
        print(f"   - {s}  ({os.path.getsize(s):,} B)")
    if len(subory) > 20:
        print(f"   ... a dalsich {len(subory)-20}")

    zasahy = collections.defaultdict(list)   # bot -> [(datum, cesta, status, ip, overene)]
    meta = {}                                # bot -> (firma, kategoria)
    celkom_riadkov = 0
    neparsovane = 0
    neplatne_ip = collections.Counter()
    vsetky_ua = collections.Counter()
    prvy_datum, posledny_datum = None, None

    for subor in subory:
        try:
            with otvor(subor) as fh:
                for riadok in fh:
                    celkom_riadkov += 1
                    m = LOG_RE.match(riadok)
                    if not m:
                        neparsovane += 1
                        continue
                    ua = m.group("ua") or ""
                    vsetky_ua[ua[:120]] += 1
                    try:
                        dt = datetime.strptime(m.group("cas").split()[0], "%d/%b/%Y:%H:%M:%S")
                    except ValueError:
                        continue
                    if prvy_datum is None or dt < prvy_datum:
                        prvy_datum = dt
                    if posledny_datum is None or dt > posledny_datum:
                        posledny_datum = dt
                    hit = klasifikuj(ua)
                    if not hit:
                        continue
                    nazov, firma, kat, ipf = hit
                    meta[nazov] = (firma, kat)
                    ip_txt = m.group("ip")
                    try:
                        ipaddress.ip_address(ip_txt)
                    except ValueError:
                        neplatne_ip[ip_txt] += 1
                    overene = ip_patri(ip_txt, ipf)
                    zasahy[nazov].append((dt, m.group("cesta"), m.group("status"),
                                          ip_txt, overene))
        except Exception as e:
            print(f"   ! chyba pri {subor}: {e}")

    print(f"\nSpracovanych riadkov: {celkom_riadkov:,}  (neparsovanych: {neparsovane:,})")
    if neplatne_ip:
        print(f"! POZOR: {sum(neplatne_ip.values())} zasahov ma necitatelnu IP "
              f"(poskodeny log?): {', '.join(repr(k) for k, _ in neplatne_ip.most_common(3))}")
    if prvy_datum:
        print(f"Obdobie logu: {prvy_datum:%Y-%m-%d %H:%M} az {posledny_datum:%Y-%m-%d %H:%M}"
              f"  ({(posledny_datum-prvy_datum).days} dni)")

    if not zasahy:
        print("\n" + "!" * 78)
        print("ZIADNY AI CRAWLER V TOMTO LOGU NEBOL NAJDENY.")
        print("!" * 78)
        print("\nTop 15 user-agentov v logu (na kontrolu, ze log je spravny):")
        for ua, n in vsetky_ua.most_common(15):
            print(f"  {n:7,}  {ua}")
        return

    # -------- suhrn podla kategorie
    print("\n" + "=" * 78)
    print("SUHRN PODLA BOTA")
    print("=" * 78)
    print(f"{'BOT':<24}{'FIRMA':<12}{'TYP':<14}{'ZASAHY':>8}{'URL':>6}{'OVER.':>7}{'FALOS':>7}")
    print("-" * 78)
    poradie = sorted(zasahy.items(), key=lambda kv: -len(kv[1]))
    for nazov, udaje in poradie:
        firma, kat = meta[nazov]
        over = sum(1 for u in udaje if u[4] is True)
        falos = sum(1 for u in udaje if u[4] is False)
        url_pocet = len({u[1] for u in udaje})
        over_s = str(over) if over or falos else "-"
        falos_s = str(falos) if over or falos else "-"
        print(f"{nazov:<24}{firma:<12}{kat:<14}{len(udaje):>8,}{url_pocet:>6}{over_s:>7}{falos_s:>7}")

    # -------- podla firmy
    print("\n" + "=" * 78)
    print("SUHRN PODLA FIRMY")
    print("=" * 78)
    podla_firmy = collections.defaultdict(int)
    for nazov, udaje in zasahy.items():
        podla_firmy[meta[nazov][0]] += len(udaje)
    for firma, n in sorted(podla_firmy.items(), key=lambda kv: -kv[1]):
        print(f"  {firma:<14} {n:>8,} zasahov")

    # -------- detail kazdeho bota
    for nazov, udaje in poradie:
        firma, kat = meta[nazov]
        print("\n" + "=" * 78)
        print(f"DETAIL: {nazov}  ({firma}, {kat})")
        print("=" * 78)
        udaje_s = sorted(udaje)
        print(f"Prva navsteva:    {udaje_s[0][0]:%Y-%m-%d %H:%M}")
        print(f"Posledna navsteva:{udaje_s[-1][0]:%Y-%m-%d %H:%M}")
        over = sum(1 for u in udaje if u[4] is True)
        falos = sum(1 for u in udaje if u[4] is False)
        if over or falos:
            print(f"Overene voci oficialnym IP: {over:,} / falosne (podvrhnuty UA): {falos:,}")
            if falos:
                fake_ips = collections.Counter(u[3] for u in udaje if u[4] is False)
                print(f"  POZOR - podvrhnute IP: {', '.join(f'{i}({n})' for i,n in fake_ips.most_common(5))}")
        else:
            print("Overenie IP: firma nezverejnuje rozsahy - nedalo sa overit")

        stat = collections.Counter(u[2] for u in udaje)
        print(f"HTTP stavy: {', '.join(f'{k}={v}' for k,v in sorted(stat.items()))}")

        print("\nCasova os (po dnoch):")
        po_dnoch = collections.Counter(u[0].strftime("%Y-%m-%d") for u in udaje)
        maxv = max(po_dnoch.values())
        for den in sorted(po_dnoch):
            n = po_dnoch[den]
            print(f"  {den}  {n:>5,}  {'#' * max(1, int(40*n/maxv))}")

        print("\nNajcastejsie stiahnute stranky:")
        for cesta, n in collections.Counter(u[1] for u in udaje).most_common(15):
            print(f"  {n:>5,}  {cesta}")

    # -------- CSV export
    csv_path = os.path.join(IPS_DIR, "ai_boti_zasahy.csv")
    with open(csv_path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh, delimiter=";")
        w.writerow(["bot", "firma", "typ", "datum_cas", "cesta", "http_status", "ip", "ip_overene"])
        for nazov, udaje in zasahy.items():
            firma, kat = meta[nazov]
            for dt, cesta, status, ip, ov in sorted(udaje):
                w.writerow([nazov, firma, kat, dt.strftime("%Y-%m-%d %H:%M:%S"),
                            cesta, status, ip,
                            {True: "ano", False: "NIE-podvrh", None: "neoveritelne"}[ov]])
    print("\n" + "=" * 78)
    print(f"CSV s vsetkymi zasahmi ulozene: {csv_path}")
    print("=" * 78)

if __name__ == "__main__":
    main()
