from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from vv_client_api import app


class Phase0Sprint01ReadOnlyClientApiTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_telemetry_ingestion_routes_are_not_exposed(self):
        openapi = self.client.get('/openapi.json')
        self.assertEqual(openapi.status_code, 200)
        paths = openapi.json().get('paths', {})

        self.assertNotIn('/api/v1/client/events', paths)
        for path in paths:
            self.assertFalse(path.startswith('/api/v1/integrations/spectrastrike'))

    def test_legacy_telemetry_ingestion_endpoints_return_not_found(self):
        payload = {'event_type': 'DASHBOARD_VIEWED', 'object_type': 'dashboard'}

        client_events = self.client.post('/api/v1/client/events', json=payload)
        self.assertEqual(client_events.status_code, 404)

        spectra_event = self.client.post('/api/v1/integrations/spectrastrike/events', json={'source_system': 'x'})
        self.assertEqual(spectra_event.status_code, 404)

    def test_read_only_resources_reject_write_methods(self):
        res = self.client.post('/api/v1/client/findings', json={})
        self.assertEqual(res.status_code, 405)


if __name__ == '__main__':
    unittest.main()
