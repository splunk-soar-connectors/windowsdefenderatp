# Copyright (c) 2026 Splunk Inc.
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

import ast
from pathlib import Path


CONNECTOR = Path(__file__).parents[1] / "microsoftdefenderforendpoint_connector.py"
SOURCE = CONNECTOR.read_text(encoding="utf-8")
TREE = ast.parse(SOURCE)


def _function_source(name: str) -> str:
    node = next(item for item in ast.walk(TREE) if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == name)
    return ast.get_source_segment(SOURCE, node) or ""


def test_login_redirect_validates_nonce_before_reading_sensitive_url():
    source = _function_source("_handle_login_redirect")
    compare_position = source.index("hmac.compare_digest")
    url_position = source.index("url = state.get(key)")

    assert 'request.GET.get("state_nonce"' in source
    assert compare_position < url_position


def test_displayed_oauth_start_link_carries_pending_nonce():
    source = _function_source("_handle_test_connectivity")

    assert 'urlencode({"asset_id": self.get_asset_id(), "state_nonce": flow_nonce})' in source
    assert 'f"{app_rest_url}/start_oauth?{start_query}"' in source


def test_temporary_handshake_state_excludes_existing_tokens():
    source = _function_source("_handle_test_connectivity")
    state_assignment = source.index('self._state = {\n                "redirect_uri"')
    save_position = source.index("_save_app_state(self._state", state_assignment)
    temporary_state = source[state_assignment:save_position]

    assert '"oauth_state_nonce": flow_nonce' in temporary_state
    assert '"authorization_url": authorization_url' in temporary_state
    assert '"token"' not in temporary_state
    assert '"access_token"' not in temporary_state
    assert '"refresh_token"' not in temporary_state


def test_oauth_files_use_the_platform_application_state_directory():
    source = _function_source("_get_file_path")

    assert "paths.PHANTOM_APP_STATES / APP_ID" in source
    assert "__file__" not in source


def test_oauth_timeout_removes_temporary_state():
    source = _function_source("_wait")
    timeout_position = source.index("if not time_out:")
    timeout_return = source.index("return action_result.set_status", timeout_position)

    assert "_get_file_path(self.get_asset_id()).unlink()" in source[timeout_position:timeout_return]
