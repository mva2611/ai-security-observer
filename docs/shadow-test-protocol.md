# Testovací protokol — 24. 10. 2026

Výsledek: **PASS pro lokální implementaci, syntetické fault-injection testy a
izolovaný databázový replay reálných dat**. Neproběhl binární IPFIX/GoFlow2
replay ani produkční deployment analytické vrstvy.

## Prostředí a běh

Oddělená kopie checkoutu HEAD `7cdf130`, Python 3.9.2, standardní sqlite3,
bez nových knihoven, bez Dockeru, NAS, produkční DB a Grafany.

```sh
python3 -m unittest discover -s tests -v
```

**114 testů PASS** (36 analytics/runtime testů a 78 stávajících testů),
10,479 s.
Testy zapisují a případně mění/mažou pouze dočasné syntetické fixtures.

## Pokrytí nových testů

| Oblast | Ověření |
|---|---|
| Replay | Opakovaný běh nic nepřičítá, restart po úspěšném commitu pokračuje |
| Duplicity | Jiná ID/sequence stejného canonical obsahu; raw je zachováno |
| Pořadí | Různé velikosti dávek i samostatný přeuspořádaný zdroj dávají stejné objemy/okna |
| Opoždění | Návrat do předchozího dne/hodiny; oprava starého okna |
| Okna | Hraniční ns před/na UTC dni a hodině, half-open intervaly |
| Konzistence | Počty, bajty a pakety hour=day; raw=canonical+duplicate+excluded+late_outside_horizon |
| Kvalita | NULL, nula, záporný čítač, reconstructed a neplatný interval/fallback |
| Identita | Unknown MAC zůstává unknown; inbound a outbound se neslučují |
| Crash | Výjimka před commitem i skutečné os._exit(23) v samostatném procesu |
| Obnova | Po pádu žádné částečné agregace ani checkpoint; integrity_check=ok |
| Gaps | Úvodní i vnitřní numerické mezery, bez tvrzení prokázané ztráty |
| Změna zdroje | Změněný/zmizelý checkpoint boundary zastaví běh |
| Kontrakty | Vadná schema/version, batch limity, source binding, read-only zápis zakázán |
| Bezpečný cíl | Odmítnutí stejné cesty a hardlink aliasu zdroje |
| Security | Aktualizace staršího mutable eventu, rollback projekce, vlastní checkpoint, detector health |
| Security sweep | Jeden zdrojový snapshot, incomplete/failed = uncertain, complete = current, zmizelý event = historical |
| Worker health | initializing/healthy/failed/stale, nová incarnation po restartu, sanitizace chyby |
| Source pass | Dílčí dávka není vydávána za dokončený průchod zdrojem |
| Časná chyba sweepu | Původní chyba před vznikem sweep ID není překryta sekundární výjimkou |
| Retence podpisů | Úplný checkpoint, boundary hash, blokace při vnitřní ID mezeře |
| Pozdní flow | Flow za uzavřeným horizontem je explicitně `late_outside_horizon` a není přičteno podruhé |
| Cleanup restart | Rollback přerušeného chunku, bezpečné navázání a idempotentní opakování |
| Migrace schématu | Staré podpisy jsou zachovány a počáteční source floor neblokuje cleanup |
| Disk full | Reálný limit SQLite, rollback dávky, checkpoint beze změny, chyba zapsaná z rezervy |
| WAL souběh | Delší paralelní writer/reader bez zápisu do zdroje |
| IPv6/NAT | IPv6 /48 fixture, NAT atributy a časová provenience |
| Baseline | Připravený vstupní pohled, žádné samovolně vytvořené modely |
| CLI | Omezený počet dávek, další spuštění navazuje |

Testy nepřehrávají binární UDP/IPFIX přes GoFlow2: nová vrstva čte již
normalizovaný SQLite kontrakt. Collector a jeho parser/mapping nebyly změněny;
existující unit testy normalizace prošly. Samostatné nástroje
validate_ipfix_time.py / validate_ipfix_nat.py s GoFlow2 a síťový PCAP replay
nebyly v tomto běhu spuštěny. Totéž platí pro dlouhodobý zátěžový test,
simulaci výpadku napájení OS/hardware. `SQLITE_FULL`, procesní pád a souběžný
WAL writer/reader jsou ověřeny na izolovaných SQLite fixtures.

## Zachovaný izolovaný replay

`artifacts/replay-flows.db` obsahuje výhradně pět syntetických řádků.
`artifacts/analytics.db` je lokálně vytvořená výstupní analytics databáze,
nikoliv produkční stav. `artifacts/replay-result.json` obsahuje součty:

| Scope | Flows | Známé bajty | Známé pakety |
|---|---:|---:|---:|
| raw | 5 | 400 | 8 |
| canonical | 3 | 200 | 4 |
| duplicate | 1 | 100 | 2 |
| excluded | 1 | 100 | 2 |

Hodinové a denní součty se shodují; evidována mezera 2→4,
opakování je idempotentní, integrity_check vrací `ok`.
Jeden řádek má neznámé bajty: 400 není tvrzení o úplném objemu.
Naměřená doba několika milisekund na pěti řádcích není benchmark kapacity.

Standalone syntetický SQLite backup byl pro tento uložený fixture otevřen
v režimu DELETE journal, aby byl samostatně read-only čitelný bez WAL/SHM.
Toto není změna zdrojové ani produkční databáze. Živý WAL zdroj vyžaduje
přístup k existujícím sidecar souborům, jak již používá detector.

## Reálný izolovaný databázový replay

Zdroj byl vytvořen jako konzistentní pracovní kopie z dříve nezávisle ověřené
záložní generace
`gen-20261024T004529.151704Z-30ae91ad`. Produkční kontejnery ani databáze nebyly
měněny. Reprezentativní výřez obsahoval přesně 260 000 řádků s ID
8 600 000–8 859 999 a přibližně šest hodin provozu kolem přechodu časové
provenience:

| Metrika | Výsledek |
|---|---:|
| Vstupní flow | 260 000 |
| `export_fallback` / `reconstructed` | 130 220 / 129 780 |
| Canonical / excluded / duplicate | 237 939 / 22 061 / 0 |
| Canonical s identitou `unknown` | 117 429 (49,35 %) |
| Vstupní bajty / pakety | 12 568 024 335 / 12 348 539 |
| Canonical bajty / pakety | 12 433 768 667 / 11 746 616 |
| Excluded bajty / pakety | 134 255 668 / 601 923 |
| Doba / propustnost | 91,279 s / 2 848,4 flow/s |
| Agregace | 13 641 (9 361 hodinových, 4 280 denních) |
| Podpisy | 237 939 |
| Konečná DB / maximum WAL | 40 435 712 B / 15 965 032 B |

Nezávislý SQL součet potvrdil všechny vstupní počty, pakety a bajty. Rozdíl
mezi 241 668 řádky na směrovaných interface kombinacích a 237 939 canonical
řádky tvoří 3 729 neglobálních či jinak nekanonických protějšků. NAT změna
source IP byla doložena u 122 397 a destination IP u 119 290 řádků; změna
source/destination portu u jednoho řádku v každé kategorii. Maximum rozdílu
mezi přijetím a koncem toku bylo 17,093 s, žádný řádek nepřekročil 60 s.

Ve zdrojové záloze nebyl žádný IPv6 flow, proto reálný replay IPv6 neprokazuje;
IPv6 /48 je pokryto pouze regresním testem. Opakovaný replay nezměnil checkpoint
ani agregace. Injektovaný pád před commitem zachoval prázdný checkpoint a po
restartu korektně zpracoval prvních 5 000 flow. Security sweep zpracoval 13
událostí a opakované ověření nevytvořilo duplicitní historii.

## Kapacita a navazující brány

SQLite `dbstat` přisoudil tabulce podpisů a jejímu indexu 37 347 328 B,
tedy 92,36 % výsledné databáze. Při dříve naměřeném průměru 831 056 flow/den
a stejném canonical poměru jde orientačně o 760 tisíc nových podpisů a přibližně
119 MB/den. Agregace přidávají zhruba 8 MB/den. Bez expirace by analytická DB
rostla přibližně 3,8 GB za 30 dní a 46 GB za rok; jde o projekci z krátkého
vzorku, nikoliv kapacitní garanci.

Retence nebyla stanovena ani aktivována. Deduplikační podpisy rostou bez
expirace a také časově detailní dimenze agregací představují neomezenou historii.
Omezený sedmidenní shadow běh lze provozovat s pevným diskovým rozpočtem a
monitoringem health/stáří. Dlouhodobé nasazení bez obsluhy je blokováno
schválením retence nebo změnou deduplikačního modelu.

## Omezení

Binární IPFIX ingest nebyl součástí testu. Baseline je pouze připravena a žádné
prahy se automaticky netrénují. Reálný vzorek neobsahoval IPv6 ani opoždění nad
60 sekund; tyto případy jsou doloženy synteticky. Test neprokazuje dlouhodobou
sezónnost, stabilitu dimenzí ani chování při skutečném výpadku napájení.
