# Prezentační vrstva AI Security Observeru

Prezentační vrstva je oddělená od Collectoru, Detectoru a shadow aggregatoru.
Grafana nečte flows.db ani security.db. Samostatná snapshot služba vytváří
pomocí SQLite Online Backup API konzistentní kopii analytics.db; Grafana ji
připojuje pouze pro čtení.

## Komponenty

- presentation/sqlite_snapshot.py atomicky publikuje read-only kopii DB.
- presentation/Dockerfile.snapshot vytváří izolovaný snapshot image.
- presentation/grafana/Dockerfile používá Grafanu 12.4.13 a instaluje
  frser-sqlite-datasource 4.0.6.
- presentation/grafana/provisioning/ deklaruje datasource a file provisioning.
- presentation/grafana/dashboards/ obsahuje čtyři verzované dashboardy.

SQLite datasource vyžaduje v každém targetu jak rawQueryText (uložený SQL
zdroj pro frontend), tak queryText (vykonávaný dotaz). Obě hodnoty musí být
shodné; kontroluje to tests/test_presentation.py.

## Externí stav a proměnné

Zkopírujte presentation/grafana/.env.example do .env na cílovém hostu,
doplňte lokální cesty, jednoznačné image tagy a náhodné administrátorské heslo.
Soubor .env musí zůstat mimo Git a mít režim nejvýše 0600.

- ANALYTICS_STATE_DIR je read-only adresář živé analytické vrstvy včetně WAL.
- PRESENTATION_DATA_DIR je zapisovatelný adresář konzistentní kopie.
- GRAFANA_DATA_DIR je perzistentní stav Grafany.
- GRAFANA_BIND_IP musí být pouze důvěryhodná LAN adresa.
- SNAPSHOT_IMAGE a GRAFANA_IMAGE jsou unikátní lokální image tagy.
- GRAFANA_ADMIN_PASSWORD je lokální secret.

Adresáře databází, Grafana state, .env, WAL/SHM a image archivy nejsou
součástí Git checkpointu.

## Sestavení a validace

Z kořene repozitáře:

    docker compose --env-file presentation/grafana/.env \
      -f presentation/grafana/compose.yaml config --quiet

    docker compose --env-file presentation/grafana/.env \
      -f presentation/grafana/compose.yaml build

Grafana base image je verzovaný tag, nikoliv digest, a SQLite plugin se během
buildu stahuje z externího katalogu. Zdrojový build je proto funkčně
reprodukovatelný, ale nikoliv zaručeně byte-for-byte. Přesné produkční image
musí být uchovány samostatným BDR image archivem a ověřeny SHA-256.

## Nasazení a ověření

Compose spouští pouze snapshot a grafana. Snapshot nemá síť a zdrojový
analytics adresář má read-only. Grafana má read-only root filesystem,
anonymní přístup je zakázán a datasource směřuje výhradně na prezentační kopii.

Po nasazení ověřte:

1. oba kontejnery jsou healthy a bez restart loopu;
2. datasource aso-analytics vrací data z prezentační kopie;
3. Grafana API obsahuje u všech 23 targetů shodné neprázdné rawQueryText
   a queryText;
4. v prohlížeči se vykreslí alespoň provozní, bezpečnostní a health panel;
5. Collector, Detector a aggregator pokračují bez změny a restartu.

Oprávněně prázdné mohou být pouze pohledy, pro které zdrojová data skutečně
neexistují, například dosud nenatrénované statistické baseline.

## Rollback

Zastavte a odstraňte pouze Compose projekt Grafany. Zachovejte
GRAFANA_DATA_DIR a PRESENTATION_DATA_DIR pro diagnostiku. Rollback nesmí
restartovat ani měnit Collector, Detector, aggregator nebo jejich databáze.
