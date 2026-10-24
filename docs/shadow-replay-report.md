# Shadow analytics — replay a kapacitní protokol, 24. 10. 2026

## Rozsah a izolace

Replay byl proveden nad konzistentní pracovní kopií ověřené generace
`gen-20261024T004529.151704Z-30ae91ad` v odděleném stagingu
`/volume1/homes/mira/ai-security-observer-shadow-replay-20261024`.
Produkční `flows.db`, `security.db`, Collector a Detector zůstaly beze změny a
po testu byly oba kontejnery stále healthy bez restartu. Neproběhl binární
IPFIX/GoFlow2 replay; ověřena byla vrstva od normalizovaných SQLite flow dál.

## Výsledek replaye

| Metrika | Hodnota |
|---|---:|
| Rozsah ID | 8 600 000–8 859 999 |
| Vstupní řádky | 260 000 |
| `export_fallback` | 130 220 |
| `reconstructed` | 129 780 |
| Canonical | 237 939 |
| Excluded | 22 061 |
| Duplicate | 0 |
| Unknown identity | 117 429 |
| Vstupní bajty | 12 568 024 335 |
| Vstupní pakety | 12 348 539 |
| Canonical bajty | 12 433 768 667 |
| Canonical pakety | 11 746 616 |
| Excluded bajty | 134 255 668 |
| Excluded pakety | 601 923 |
| Doba | 91,279 s |
| Propustnost | 2 848,4 flow/s |
| Podpisy | 237 939 |
| Agregace | 13 641 |
| `analytics.db` | 40 435 712 B |
| Maximum WAL | 15 965 032 B |

Nezávislý SQL součet potvrdil počet řádků, pakety a bajty. Opakovaný replay
zpracoval nula nových flow a nezměnil agregace. Přerušení před transakčním
commitem neposunulo checkpoint; následný proces navázal korektně. Integrity
check cílové databáze skončil `ok`.

## Kvalita a pokrytí

- IPv4: 260 000 řádků; IPv6: ve zdrojové záloze nebyl žádný řádek.
- Některé NAT údaje byly přítomné u všech 260 000 řádků.
- NAT source IP se změnila u 122 397 a destination IP u 119 290 řádků.
- Časová provenience se rozdělila téměř napůl mezi `export_fallback` a
  `reconstructed`; `absolute` ve výřezu nebyla.
- Nebyl nalezen řádek s přijetím více než 60 sekund po konci flow; maximum bylo
  17,093 sekundy. Opožděné flow jsou proto prokázány jen syntetickými testy.
- Security projection přečetla 13 událostí v úplném sweepu. Druhý sweep pouze
  obnovil ověření a nevytvořil duplicitní historii.

## Kapacitní závěr

Podpisy a jejich index zabraly 37 347 328 B (92,36 % databáze). Při zachování
pozorovaného poměru a průměru 831 056 flow/den vychází orientační růst celé
analytické vrstvy na přibližně 127 MB/den, 3,8 GB/30 dní a 46 GB/rok. Krátký
vzorek nezachycuje sezónnost a projekce má odpovídající nejistotu.

**GO — pouze pro omezený sedmidenní produkční shadow provoz** s oddělenou DB,
pevným diskovým rozpočtem, health kontrolou a možností kontejner zastavit bez
vlivu na Collector/Detector. **NO-GO pro dlouhodobý set-and-forget provoz**, dokud
nebude schválena retence podpisů a agregací nebo kompaktnější deduplikační model.
