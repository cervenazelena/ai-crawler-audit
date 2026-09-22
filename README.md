# AI Crawler Audit

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22902220.svg)](https://doi.org/10.5281/zenodo.22902220)

Nástroj na zistenie, **ktoré AI crawlery reálne navštevujú váš web** — a ktoré sa za ne len vydávajú.

Vyvinuté pre [cervenazelena.sk](https://www.cervenazelena.sk/) pri výskume toho, ako sa obsah slovenského webu dostáva do veľkých jazykových modelov.

---

## Načo to je

Keď sa pýtate „sleduje moju stránku OpenAI alebo Anthropic?", existuje presne jedna spoľahlivá odpoveď: **serverové logy**. Nič iné to nepovie.

- Analytika v JavaScripte (Google Analytics, Matomo) boty **nezachytí** — crawlery JavaScript nespúšťajú.
- User-agent v logu sa dá sfalšovať jedným riadkom `curl`, takže `grep GPTBot` vás pokojne oklame.

Tento nástroj preto porovnáva IP adresu každého zásahu s **oficiálnymi rozsahmi, ktoré prevádzkovatelia zverejňujú**, a podvrhy rovno označí.

## Čo to vie

- rozpoznáva **34 crawlerov** (OpenAI, Anthropic, Google, Perplexity, ByteDance, Meta, Apple, Amazon, Cohere, Mistral, Common Crawl a ďalšie)
- overuje pravosť proti **~1 950 oficiálnym IP prefixom** od OpenAI, Anthropic a Google
- rozlišuje tri druhy návštev, čo je pri interpretácii kľúčové:
  - `TRENING` — crawler zbiera dáta na trénovanie modelu (GPTBot, ClaudeBot, CCBot)
  - `VYHLADAVANIE` — buduje index pre AI vyhľadávanie (OAI-SearchBot, Claude-SearchBot)
  - `ZIVY_FETCH` — model si stránku stiahol **priamo na žiadosť používateľa**, čiže obsah sa v tej chvíli objavil v odpovedi (ChatGPT-User, Claude-User)
- časová os po dňoch, zoznam stiahnutých stránok, HTTP stavy, export do CSV

## Použitie

```bash
git clone https://github.com/cervenazelena/ai-crawler-audit.git
cd ai-crawler-audit
python stiahni_ip_rozsahy.py                 # raz na začiatku, potom občas znova
python analyza_ai_botov.py /cesta/k/logom/   # súbor, adresár aj .gz archívy
```

Očakáva Apache/nginx **combined** formát. Beží na čistom Python 3.8+, žiadne závislosti.

## Priebežné logovanie na WordPresse

`ai-bot-logger.php` nahrajte do `wp-content/mu-plugins/`. Aktivuje sa sám, zapisuje mesačné súbory v tom istom formáte, takže ich číta rovnaký analyzátor.

**Nenahrádza serverové logy, dopĺňa ich.** Plugin nevidí požiadavky, ktoré neprejdú cez WordPress — a to je práve `/robots.txt`, čiže najčistejší signál, že crawler dorazil. Nevidí ani to, čo odbaví serverová cache bez spustenia PHP. Serverový log zas býva po pár mesiacoch rotáciou zmazaný. Spolu sa kryjú.

## Na čo si dať pozor

**`Google-Extended` v logoch nikdy neuvidíte.** Nie je to crawler ani user-agent, je to **iba token do `robots.txt`**. Obsah pre tréning Gemini sťahuje bežný `Googlebot` a Google nijako nerozlišuje, čo skončí vo vyhľadávaní a čo v modeli. Z logov sa teda dá zistiť len to, že Googlebot chodí — a či `Google-Extended` máte alebo nemáte zakázaný. Pri OpenAI a Anthropic je to jednoznačné, tam sú crawlery samostatné a overiteľné.

**Nie každý zverejňuje rozsahy.** Perplexity, ByteDance, Meta a ďalší nie. Ich zásahy dostanú `neoveriteľné` — nie `pravé`.

**Overená IP potvrdzuje pôvod, nie úmysel.** Hovorí, že požiadavka prišla z infraštruktúry firmy. Čo s dátami ďalej spravia, z logu nevyčítate.

## Citovanie

Archivované na Zenode s trvalým DOI. Tento odkaz vedie vždy na najnovšiu verziu:

> ČZ o.z. (2026). *AI Crawler Audit: overovanie návštev AI crawlerov v serverových logoch*.
> Zenodo. https://doi.org/10.5281/zenodo.22902220

## Licencia

MIT — viď [LICENSE](LICENSE).

## Autor

Vydáva [ČZ o.z.](https://www.cervenazelena.sk/kto-sme/), vydavateľ časopisu
[Červená Zelená](https://www.cervenazelena.sk/) (ISSN 2989-4131).
