# Copyright (c) 2025-2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Output-mapping quirks in _alert_to_output."""

import json

from src.app import _alert_to_output


def test_tags_flattened_to_comma_joined_string():
    alert = {"id": "TST-1", "tags": [{"name": "phishing"}, "raw-tag"]}
    assert _alert_to_output(alert)["tags"] == "phishing,raw-tag"


def test_entity_content_json_dumped():
    content = {"root_domain": {"ip_address": "203.0.113.7"}}
    out = _alert_to_output({"id": "TST-1", "entity_content": content})
    assert json.loads(out["entity_content"]) == content


def test_entity_content_absent_maps_to_none():
    assert _alert_to_output({"id": "TST-1"})["entity_content"] is None


def test_last_activity_fallback_key():
    out = _alert_to_output({"id": "TST-1", "last_activity": "2026-09-10T00:00:00"})
    assert out["last_activity_timestamp"] == "2026-09-10T00:00:00"


def test_last_activity_timestamp_preferred():
    out = _alert_to_output(
        {
            "id": "TST-1",
            "last_activity_timestamp": "2026-09-10T01:00:00",
            "last_activity": "2026-09-09T00:00:00",
        }
    )
    assert out["last_activity_timestamp"] == "2026-09-10T01:00:00"
