# Shadow analytics — lokální návrh, 24. 10. 2026

## Ověřený výchozí stav a hranice auditu

Původní checkout `/Users/mvacula/ai-security-observer` má HEAD
`7cdf130` (graceful shutdown detectoru). Již před touto prací obsahoval
necommitované `backup/`, `docs/architecture-and-roadmap.md`,
`docs/backup-and-recovery.md` a `tests/test_backup_recovery.py`.
Tyto změny byly převzaty do oddělené pracovní kopie beze změny.
Collector, detector, compose, zálohy a jejich původní testy nebyly upraveny.

Ověřeny byly `collector/schema.sql`, `collector/flowstore.py`,
`detector/security_schema.sql`, `detector/security_reader.py`,
`detector/detection.py` a architektonická dokumentace. Přístup ke zdrojovým
DB používá `mode=ro` a `query_only`; nepoužívá `immutable`, aby nebyl ignorován WAL.
Zdrojové DB ani přístup k NAS nebyly pro tuto implementaci potřeba.

Odkazovaný chat „Návrh termínu commitů“ vrací asistentské zprávy jen jako
content-reference placeholdery. Jejich podrobný obsah nebyl dostupný.
Z navazujícího chatu „Navázat s Codexem“ je dostupné uživatelské potvrzení PASS
pro backup task 14 (úterý/sobota 01:30, UID 1026, bez souběhu). Jde o převzatou
auditní evidenci, nikoliv nově provedený audit NAS. Zálohy se zde nemění.
Zásady z aktuálního zadání mají přednost před starší roadmapou.

## Kontrakty a význam dat

- `flows.id`: INTEGER PRIMARY KEY, rostoucí kurzor nově vložených neměnných řádků.
  Collector při INSERT ID nepředává; analytics nepředpokládá souvislou číselnou řadu.
  Ověřuje všechny existující normalizované sloupce a schema_version=1 v každé dávce.
- Časy jsou integer nanosekundy. Provenience je `absolute`, `reconstructed`,
  `export_fallback`. Použije se stávající validace intervalu collectoru.
- Okna jsou UTC `[start,end)`, podle flow_end_ns. Neplatný interval jde podle
  received_at_ns s vlastní kategorií `invalid_fallback`. Ani platný
  export_fallback se nevydává za přesný čas komunikace. Celý flow se přiřazuje
  jednomu oknu konce; bajty se nerozpočítávají podle délky toku.
- Canonical scope používá přímo existující `normalize_traffic` a jeho podpis.
  LAN/WAN jsou ověřené stávající hodnoty 10/8. Rozdílné směry zůstávají oddělené;
  příchozí NAT provoz bez historické MAC zůstává `unknown`. Žádné současné DHCP
  mapování se nepoužívá. Analytics neprovádí detekci R2/R4.
- Podpis není IPFIX sequence_num. Sequence není unikátní identifikátor flow.
  Stejný canonical obsah je potlačen i pod jiným ID/sequence; přesně to je
  heuristika stávajícího detectoru, nikoliv důkaz totožnosti dvou komunikací.
  Analytics uchovává podpisy déle než dnešní sedmidenní cache detectoru;
  jejich součty proto nemusejí být identické s historickými počítadly R2.
- Peer je IPv4 /24 nebo IPv6 /48, služba zachovává protokol a port.
  Zdrojové detaily a evidence zůstávají ve flows/security DB; analytics je nekopíruje.
- `raw = canonical + duplicate + excluded + late_outside_horizon` pro počty i
  známé nezáporné čítače.
  Chybějící čítač má samostatný počet, nikoliv tvrzenou nulu. Záporný či necelý
  čítač se nezapočítá do objemu a zvýší invalid_counters (počet vadných polí).
  Prezentace musí zobrazovat neúplnost součtů.
- `late_flows` označuje čas konce menší než dosavadní maximum časů při čtení
  podle ID, tedy časové přeuspořádání, nikoliv měření síťové latence.
  Starší okna zůstávají opravitelná; neexistuje automatická finalizace.

## Zápis a restart

Nová `analytics.db` má vlastní checkpointy `flows` a `security`. Součty,
trvalé podpisy, numerické gaps, flow checkpoint a health se commitují atomicky
v jedné transakci s WAL/synchronous=FULL. Čtení zdrojové dávky má vlastní
read snapshot. Pád před commitem nezanechá částečné výsledky, po commitu
restart pokračuje za uloženým ID. Cíl nesmí být aliasem zdroje ani jeho WAL/SHM.

Cesta zdrojů, interface konfigurace a verze významu agregace jsou navázány na DB.
Změna vyžaduje novou analytics DB. U checkpointu se ověřuje hash celého
zdrojového řádku; zmizelý či změněný boundary nebo rollback maxima zastaví běh.
Neměnnost všech dříve přečtených řádků není opakovaně skenována. Vložení ID
pod checkpoint nelze tímto kurzorem odhalit: zdroj musí dodržovat append-only
kontrakt. Obnova zdroje vyžaduje explicitní kontrolu generace a nový replay;
checkpoint se automaticky neresetuje.

Numerické mezery se evidují včetně úvodní mezery. Nejsou automaticky označeny
jako ztráta telemetrie. IPFIX export může ztratit pakety ještě před collectorem,
což z SQLite ID zjistit nelze. Nejde o záruku úplnosti síťových pozorování.

Security projection používá restartovatelný keyset sweep podle `event_id`, ale
celý průchod zdrojem probíhá v jediné read transakci. Průběžné stránky se proto
nemohou tvářit jako několik nesouvisejících snapshotů. Teprve atomické dokončení
celého sweepu označí viděné řádky jako `current`; do té doby jsou projekce
`uncertain`. Události, které v úplném novém sweepu chybějí, se nemažou, ale
přejdou na `historical`. Historie změn payloadu je append-only v
`security_projection_history`.

U každé projekce jsou odděleny původní časy události (`created_at_ns`,
`first_seen_ns`, `last_seen_ns`), první projekce, poslední ověření a čas
dokončení zdrojového sweepu. Stará kopie se tím nevydává za aktuální auditní
pravdu a původ i předchozí obsah zůstávají dohledatelné.

Runtime health je vázán na konkrétní `incarnation_id`. Start procesu vždy
nastaví `initializing`; úspěšný commit nastaví `healthy`, zachycená chyba
`failed` a překročené stáří heartbeat `stale`. Starý úspěch z předchozího
procesu proto po restartu automaticky neznamená zdravý worker. Diagnostika
ukládá čas, typ a sanitizovanou příčinu poslední chyby. Rezervovaná stránka DB
umožní zaznamenat i `SQLITE_FULL`, aniž by se posunul checkpoint.
Rozhraní na to musí upozornit a umožnit dohledat originál.

## Připravené prezentační a baseline kontrakty

- Přehled sítě: `presentation_overview`, oddělené scope, hodinové/denní objemy.
- Detail zařízení/služeb: `aggregates`, identita, směr, peer prefix, protokol,
  port, časová provenience a kvalita. Chybějící řádek neznamená prokázanou nulu.
- Security: kompatibilní `presentation_security` a nový
  `presentation_security_v2`, který navíc zpřístupňuje freshness, poslední
  ověření a dokončení sweepu; statistická novost není incident.
- Health: `presentation_health` (analytics polling, checkpoint, ID span a gaps),
  `presentation_worker_health` (aktuální incarnation workeru) a
  `presentation_detector_health` (samostatný snapshot detectoru).
  Pending ID span není počet chybějících řádků. Stáří polling/refreshed_ns musí
  vyhodnotit čtenář; tyto pohledy samy neposílají alerty.
- Baseline: `baseline_hourly_inputs` s UTC hodinou a dnem týdne;
  `baseline_models` s verzí, trénovacím intervalem, stavem a parametry.
  Modely jsou zatím prázdné, žádná baseline ani prahy se automaticky netrénují.
  Před tréninkem vybrat kvalitní úplná období a schválit politiku driftu.

Grafana, její SQLite datasource a čtyři dashboardy jsou nasazeny jako oddělená
prezentační vrstva nad konzistentní read-only kopií analytics.db. Podrobný
provozní kontrakt, externí závislosti a rollback popisuje
docs/presentation.md.

## Lokální použití

Z kořene oddělené kopie, pouze s izolovanými nebo schválenými zdroji:

```sh
python3 -m analytics.shadow /cesta/k/flows.db /samostatny/adresar/analytics.db \
  --security-db /cesta/k/security.db --batch-size 1000 --max-batches 100

# Diagnostika bez dashboardu
python3 -m analytics.shadow /cesta/k/flows.db /samostatny/adresar/analytics.db \
  --health --stale-seconds 300
```

Jedno spuštění má omezený počet dávek pro každý zdroj a pak skončí.
Další spuštění naváže. Žádný scheduler či služba nebyly instalovány.
Podpisy mají sedmidenní deduplikační horizont založený na zpracovaném ID
checkpointu a high-watermarku event time. Cleanup je povolen pouze po úplném
průchodu neměnným zdrojovým snapshotem, s ověřeným boundary hashem a bez vnitřní
mezery ID. Každá cleanup transakce smaže nejvýše 10 000 podpisů a jeden běh má
nejvýše 100 krátkých transakcí. Přerušený cyklus bezpečně naváže při dalším
spuštění. Flow doručené později s časem před uzavřenou hranicí se nezařadí znovu
jako canonical, ale explicitně do `late_outside_horizon`. Počítá se do raw a
diagnostiky, takže není tiše ztraceno ani dvojitě započteno.

Cleanup nespouští `VACUUM`; uvolněné stránky SQLite se znovu použijí. Agregace
zatím nemají aktivní retenci. Doporučený budoucí kontrakt je 30 dní hodinových
a 365 dní denních agregací, teprve po kontrole úplnosti příslušných denních
bucketů a zachování trvalých security důkazů.
