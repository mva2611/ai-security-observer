# Shadow analytics — bounded signature retention, 24. 10. 2026

## Retenční kontrakt

Canonical podpis se již neuchovává neomezeně. Každý podpis obsahuje event-time
a zdrojové flow ID. Sedmidenní hranice se smí posunout pouze tehdy, když:

1. analytics checkpoint přesně odpovídá aktuálnímu `MAX(flows.id)`;
2. hash řádku na checkpointu stále souhlasí;
3. ve zpracovaném rozsahu není žádná vnitřní numerická mezera ID;
4. celý aktuální zdrojový snapshot byl dokončen.

Časová hranice je `max_seen_event_time - horizon`, ale nikdy se nepoužívá bez
výše uvedeného důkazu ingest pořadí a úplnosti. Po atomickém uzavření hranice
se staré podpisy mažou po nejvýše 10 000 řádcích na transakci a maximálně ve
100 transakcích na jeden cyklus. Pád vrátí pouze aktuální chunk; další spuštění
bezpečně pokračuje.

Flow s vyšším ID, které dorazí až po uzavření hranice, ale jeho event-time je
starší než `closed_before_ns`, není znovu canonical. Je evidováno ve scope
`late_outside_horizon` a v `signature_retention.late_outside_total`. Zůstává
součástí raw součtů, takže nejde o tiché přeskočení.

## Reálný replay

Oba běhy použily stejnou izolovanou kopii 260 000 reálných flow. Produkční
Collector, Detector a jejich databáze nebyly připojeny pro zápis ani změněny.

| Metrika | 7 dní | Měřicí horizont 1 hodina |
|---|---:|---:|
| Čas replaye | 95 s | 116 s |
| Canonical flow | 237 939 | 237 939 |
| Excluded flow | 22 061 | 22 061 |
| Podpisy po cleanupu | 237 939 | 32 914 |
| Smazané podpisy | 0 | 205 025 |
| Agregované řádky | 13 641 | 13 641 |
| Fyzická DB | 48 861 184 B | 48 861 184 B |
| Odhad živých stránek | 48 861 184 B | 11 599 872 B |
| Stránky připravené k reuse | 0 B | 37 261 312 B |
| Maximum WAL | 16 146 312 B | 18 783 112 B |
| Integrity check | `ok` | `ok` |

Fyzický soubor se bez `VACUUM` nezmenšil, ale 37,3 MB stránek je okamžitě
použitelných pro další zápisy. To je zamýšlené provozní chování a nevyžaduje
blokující přepis databáze.

Po cleanupu byl do pracovní kopie vložen skutečný starý flow se stejným
canonical podpisem a novým ID. Výsledek: raw se zvýšilo na 260 001,
`late_outside_horizon=1`, canonical zůstalo 237 939 a počet podpisů 32 914.
Druhé spuštění nic dalšího nepřičetlo; checkpoint skončil na 8 860 000 a
integrity check zůstal `ok`.

## Unknown identity

Z 117 429 canonical flow s identitou `unknown`:

- 117 427 bylo inbound WAN→LAN. NAT jednoznačně poskytuje interní IP, ale
  exportované MAC adresy patří routeru. Bez časové IP/MAC inventory nelze
  trvale prokázat konkrétní zařízení.
- pouze 2 byly outbound LAN→WAN; oba řádky měly `src_mac=00:00:00:00:00:00`.

Nejde tedy o plošnou chybu mapování dostupných MAC. Pro outbound profily je
pokrytí identity 120 510 z 120 512 canonical flow (99,998 %). Inbound provoz
musí v baseline zůstat `unknown`, dokud nebude dostupná historická inventory;
současné DHCP mapování se zpětně používat nesmí.

## Kapacitní odhad

Rozdíl živých stránek odpovídá přibližně 182 B na jeden podpis včetně indexu.
Při dříve naměřeném průměru zhruba 760 tisíc canonical flow denně vychází
sedmidenní množina podpisů přibližně na 0,97 GB. Agregace přidávají orientačně
8 MB denně.

Pro budoucí stabilní stav se doporučuje, zatím bez aktivace mazání:

- podpisy: 7 dní;
- hodinové agregace: 30 dní;
- denní agregace: 365 dní;
- security evidence a auditní historie: samostatná dlouhodobá politika, bez
  automatického odvození z retence síťových agregací.

Při této politice je odhad ustálené `analytics.db` přibližně 1,5 GB plus
krátkodobý WAL a SQLite režie. Odhad vychází z krátkého vzorku a musí být během
shadow provozu porovnán se skutečným sedmidenním high-watermarkem.

## Rozhodnutí

**GO pro omezený sedmidenní shadow provoz.** Cleanup je fail-closed, late flow
má explicitní diagnostiku a reálný replay zachoval všechny součty.

Retence hodinových a denních agregací zatím není aktivní. Dlouhodobý provoz bez
kapacitního monitoringu proto zůstává podmíněn samostatným ověřením agregační
retence a úplnosti bucketů.
