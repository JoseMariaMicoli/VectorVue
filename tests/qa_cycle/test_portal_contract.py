# Copyright (c) 2026 NyxeraLabs
# Author: José María Micoli
# Licensed under BSL 1.1
# Change Date: 2033-02-17 → Apache-2.0
#
# You may:
# ✔ Study
# ✔ Modify
# ✔ Use for internal security testing
#
# You may NOT:
# ✘ Offer as a commercial service
# ✘ Sell derived competing products

from __future__ import annotations

import re
import unittest
from pathlib import Path

import requests

from tests.qa_cycle.common import BASE_URL


class TestPortalApiContract(unittest.TestCase):
    @staticmethod
    def _normalize_path_for_compare(path: str) -> str:
        # Normalize dynamic token names so /x/{id} and /x/{report_id} compare equally.
        return re.sub(r"\{[^/]+\}", "{}", path)

    def test_proxy_routes_target_existing_backend_paths(self):
        openapi = requests.get(f"{BASE_URL}/openapi.json", timeout=20)
        self.assertEqual(openapi.status_code, 200, openapi.text[:300])
        paths = set(openapi.json().get("paths", {}).keys())
        normalized_openapi = {self._normalize_path_for_compare(p) for p in paths}

        proxy_root = Path("portal/app/api/proxy")
        route_files = sorted(proxy_root.rglob("route.ts"))
        self.assertTrue(route_files, "no portal proxy routes found")

        missing: list[str] = []
        pattern = re.compile(r"proxyClientApi\(request,\s*`?([^\)`']+)`?\)")
        for route_file in route_files:
            content = route_file.read_text(encoding="utf-8")
            for raw in pattern.findall(content):
                # Remove template query parts and dynamic fragments.
                normalized = raw.split("${q ?")[0]
                normalized = normalized.replace("${params.id}", "{id}")
                normalized = normalized.replace("${params.findingId}", "{finding_id}")
                normalized = normalized.replace("${context.params.campaignId}", "{campaign_id}")
                normalized = normalized.split("?")[0]
                if self._normalize_path_for_compare(normalized) not in normalized_openapi:
                    missing.append(f"{route_file}: {normalized}")

        self.assertFalse(missing, "proxy routes targeting missing backend paths:\n" + "\n".join(missing))


if __name__ == "__main__":
    unittest.main()
