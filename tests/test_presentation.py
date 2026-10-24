import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from presentation.sqlite_snapshot import snapshot

ROOT=Path(__file__).resolve().parents[1]


class PresentationTest(unittest.TestCase):
    def test_consistent_query_only_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'source.db'; copy=Path(tmp)/'copy.db'
            db=sqlite3.connect(source); db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE evidence(id INTEGER PRIMARY KEY,value TEXT)')
            db.execute("INSERT INTO evidence(value) VALUES('one')"); db.commit()
            snapshot(source,copy)
            restored=sqlite3.connect(f'file:{copy}?mode=ro',uri=True)
            self.assertEqual(restored.execute('PRAGMA quick_check').fetchone()[0],'ok')
            self.assertEqual(restored.execute('SELECT count(*) FROM evidence').fetchone()[0],1)
            with self.assertRaises(sqlite3.OperationalError):
                restored.execute("INSERT INTO evidence(value) VALUES('forbidden')")
            restored.close(); db.close()

    def test_dashboards_are_versioned_and_use_only_analytics(self):
        dashboards=ROOT/'presentation/grafana/dashboards'
        expected={'aso-security','aso-network','aso-learning','aso-health'}
        loaded=[json.loads(path.read_text()) for path in dashboards.glob('*.json')]
        self.assertEqual({item['uid'] for item in loaded},expected)
        target_count=0
        for dashboard in loaded:
            self.assertTrue(dashboard['panels'])
            encoded=json.dumps(dashboard)
            self.assertNotIn('flows.db',encoded)
            self.assertNotIn('security.db',encoded)
            for panel in dashboard['panels']:
                if 'datasource' in panel:
                    self.assertEqual(panel['datasource']['uid'],'aso-analytics')
                    for target in panel.get('targets', []):
                        target_count += 1
                        self.assertIn('rawQueryText', target)
                        self.assertIn('queryText', target)
                        self.assertNotIn('rawSql', target)
                        self.assertEqual(target['rawQueryText'], target['queryText'])
                        self.assertTrue(target['queryText'].strip())
        self.assertEqual(target_count,23)

    def test_compose_never_mounts_raw_sources_into_grafana(self):
        compose=(ROOT/'presentation/grafana/compose.yaml').read_text()
        grafana=compose.split('  grafana:',1)[1]
        self.assertNotIn('FLOW_SOURCE',compose)
        self.assertNotIn('SECURITY_SOURCE',compose)
        self.assertNotIn('/analytics:',grafana)
        self.assertIn('/var/lib/grafana/presentation:ro',grafana)
        self.assertIn('GF_AUTH_ANONYMOUS_ENABLED: "false"',grafana)

    def test_environment_contract_and_safe_build_context(self):
        compose=(ROOT/'presentation/grafana/compose.yaml').read_text()
        example=(ROOT/'presentation/grafana/.env.example').read_text()
        required={
            'ANALYTICS_STATE_DIR','PRESENTATION_DATA_DIR','GRAFANA_DATA_DIR',
            'GRAFANA_BIND_IP','SNAPSHOT_IMAGE','GRAFANA_IMAGE',
            'GRAFANA_ADMIN_PASSWORD',
        }
        self.assertEqual(
            {line.split('=',1)[0] for line in example.splitlines()
             if line and not line.startswith('#')},
            required,
        )
        for name in required:
            self.assertIn(chr(36)+'{'+name,compose)

        ignored=(ROOT/'.dockerignore').read_text().splitlines()
        self.assertIn('**/.env',ignored)
        self.assertIn('**/*.db',ignored)
        for required_path in (
            'analytics/','collector/','detector/','deploy/','presentation/',
        ):
            self.assertNotIn(required_path,ignored)


if __name__=='__main__': unittest.main()
