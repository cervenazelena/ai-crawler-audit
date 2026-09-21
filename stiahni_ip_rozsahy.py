#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Stiahne oficiálne IP rozsahy AI crawlerov, proti ktorým sa overuje pravosť botov.

Bez týchto súborov analyzátor beží, ale nevie odlíšiť pravého GPTBota
od útočníka, ktorý si jeho user-agent iba nastavil. Spustite pred prvou analýzou
a potom občas znova — rozsahy sa menia.

Použitie:
    python stiahni_ip_rozsahy.py
"""
import json
import os
import urllib.request

ZDROJE = {
    "ips_openai_gptbot.json":        "https://openai.com/gptbot.json",
    "ips_openai_searchbot.json":     "https://openai.com/searchbot.json",
    "ips_openai_chatgpt_user.json":  "https://openai.com/chatgpt-user.json",
    "ips_anthropic.json":            "https://claude.com/crawling/bots.json",
    "ips_google_googlebot.json":     "https://developers.google.com/static/search/apis/ipranges/googlebot.json",
    "ips_google_special.json":       "https://developers.google.com/static/search/apis/ipranges/special-crawlers.json",
    "ips_google_user_triggered.json":"https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers.json",
}

CIEL = os.path.dirname(os.path.abspath(__file__))


def main():
    spolu = 0
    chyby = 0
    for subor, url in ZDROJE.items():
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=60) as r:
                text = r.read().decode("utf-8")
            data = json.loads(text)          # overíme, že je to platný JSON
            pocet = len(data.get("prefixes", []))
            with open(os.path.join(CIEL, subor), "w", encoding="utf-8") as fh:
                fh.write(text)
            print(f"{subor:<34} {pocet:>5} prefixov")
            spolu += pocet
        except Exception as e:
            print(f"{subor:<34} CHYBA: {e}")
            chyby += 1

    print(f"\nSpolu {spolu} IP prefixov v {len(ZDROJE) - chyby} súboroch.")
    if chyby:
        print(f"POZOR: {chyby} zdrojov sa nepodarilo stiahnuť — overovanie bude neúplné.")
    print("\nPoznámka: Perplexity, ByteDance, Meta a ďalší svoje rozsahy nezverejňujú.")
    print("Ich zásahy analyzátor označí ako 'neoveriteľné', nie ako pravé.")


if __name__ == "__main__":
    main()
