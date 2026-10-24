# Shadow analytics — deployment manifest

## Izolace

`analytics-shadow` je samostatný Compose projekt. Nemá síť, porty ani
capabilities. Celé adresáře zdrojových databází jsou připojeny read-only, aby
SQLite viděla také jejich WAL/SHM. Jediný write mount je samostatný adresář
`analytics.db` a provozního JSONL logu.

První start nové čisté DB nastaví checkpoint na aktuální `MAX(flows.id)` a
uloží boundary hash. Historie před bootstrapem se nepřehrává. Restart nikdy
existující checkpoint neposune. Collector a Detector nejsou součástí Compose
projektu aggregatoru.

Runtime má nízké CPU shares, 192MB memory limit, `nice=10`, omezené dávky a
pětisekundový poll. Synology kernel neposkytuje spolehlivý hard I/O throttle;
ochranu I/O proto tvoří bootstrap bez catch-up, malé dávky a oddělený proces.
Vlastní databáze má tvrdý limit 1,5 GiB; jeho překročení nastaví stav workeru na
`failed` a ukončí pouze aggregator. Compose povolí nejvýše tři automatické
restarty, nikoli nekonečný restart loop.

## První aktivace

1. Ověřit Collector/Detector, WAL a jejich restart count.
2. Vytvořit prázdný state adresář ve vlastnictví UID 1026:GID 100, mode 0700.
3. Ověřit, že `analytics.db`, `-wal` ani `-shm` neexistují.
4. Sestavit unikátní image tag podle Git commitu a zaznamenat image ID.
5. Validovat výsledný Compose manifest.
6. Spustit pouze projekt `analytics-shadow`.
7. Ověřit `initialized=true`, bootstrap ID a boundary proti read-only zdroji.
8. Po nových flow porovnat raw počty/bajty/pakety v rozsahu
   `(bootstrap_id, checkpoint]` s nezávislým SQL dotazem.
9. Restartovat pouze aggregator a potvrdit beze změny součtů.

Produkční preflight na DS923+ ověřil zdroje
`/var/services/homes/mira/ai-security-observer/data` a
`/var/services/homes/mira/ai-security-observer/security-v05`; nový samostatný
state je `/var/services/homes/mira/ai-security-observer/analytics-shadow`.

## Sedmidenní metriky

`daily_metrics` a `/state/analytics-runtime.jsonl` uchovávají checkpoint, lag,
throughput, scopes, unknown, počet dimenzí, velikost/freelist SQLite a stav
cleanupu. Kontrola nemá posílat pravidelné notifikace; upozornění je vhodné jen
pro `failed`, `stale`, vnitřní source gap, nenulový `late_outside_horizon`,
restart loop nebo překročení 1,5GB bezpečnostního limitu.

## Rollback

Zastavit a odstranit pouze Compose projekt aggregatoru. State adresář zachovat
pro diagnostiku. Protože oba zdroje jsou read-only a projekt nemá síť, rollback
nevyžaduje změnu ani restart Collectoru, Detectoru, MikroTiku či záloh.
