# Vyhodnocení lokální implementace — 24. 10. 2026

Verdikt: vhodné pro další izolované ověřování. Zatím nedoporučeno k produkčnímu
shadow nasazení ani k dlouhodobému bezobslužnému provozu.

Review provedeno nad analytics/shadow.py, schema.sql, testovacím protokolem a
výsledkem celé sady 96 PASS. Jde o vlastní kontrolu implementace, ne nezávislý
externí audit. Testovací sada při tomto review nebyla znovu spouštěna; od
posledního běhu nebyla měněna výkonná logika.

## Co je doloženo

- Adicí oddělená vrstva bez změny collector/detector/backup runtime.
- Read-only zdroje, vlastní kurzory, atomická dávka a restart po pádu.
- Hodinová/denní okna, pozdní příchozí flow, scope conservation a neznámé čítače.
- Syntetické testy a patch aplikovatelný na původní checkout.

## Co před řízeným shadow během doplnit nebo prokázat

1. Reprezentativní konzistentní kopie skutečných flows/security dat. Pět
   syntetických řádků a unit testy neprokazují kapacitu ani skutečnou kvalitu
   historické telemetrie. Změřit součty nezávislou referencí, dobu catch-up,
   velikost podpisů/agregací a chování vadných historických řádků.
2. Přehlednější stav selhání. runtime_health aktualizuje jen úspěšné dávky;
   chyba zanechá minulý úspěch a skončí výjimkou procesu. V budoucím runtime
   musí být jednoznačný failed/stale stav a dohledatelná příčina. Nesmí se
   zaměnit čerstvý poslední úspěch za stále zdravý worker.
3. Explicitní úplnost security projekce. Dnešní view zahrnuje i staré kopie;
   refreshed_ns a dokončení sweepu jsou dostupné odděleně. Před použitím jako
   přehled aktuálního stavu doplnit přímo čitelnou informaci o stáří a příslušnosti
   k dokončenému průchodu. Smazané či zmizelé zdrojové eventy nelze vydávat za
   právě potvrzené; zobrazení musí uchovat jejich původ a nejistotu.
4. Kapacitní a provozní limity. Podpisy neexpirují, agregace rostou podle
   dimenzí; raw má navíc rozdělení duplicate/excluded. Je nutné měření růstu,
   volného místa, rychlosti přítoku a dohodnutá reakce na nedostatek prostoru.
   Retence ani mazání se tímto review neschvalují.
5. Rozšířit cílené ověření před runtime schválením: IPv6, rozmanité NAT
   reprezentace a časové fallbacky z reálné kopie, disk-full/write failures,
   delší souběh WAL writeru/readeru. Dosavadní parser testy nenahrazují nový
   end-to-end binární IPFIX replay; ten nebyl proveden.

## Doporučené pořadí pokračování

Nejprve lokálně zpevnit health a explicitní freshness/úplnost projekcí,
aktualizovat cílené testy a diff. Následně použít existující ověřenou backup
kopii pro read-only izolovaný replay a kapacitní protokol. Teprve podle těchto
výsledků předložit konkrétní runtime manifest a rozhodnutí o řízeném shadow
nasazení. Grafana a retenční změny zůstávají následnými samostatnými kroky.

Žádné produkční změny nebyly v rámci tohoto vyhodnocení provedeny.
