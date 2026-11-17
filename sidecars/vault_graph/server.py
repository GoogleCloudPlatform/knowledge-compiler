#!/usr/bin/env python3
# Copyright 2026 Google LLC
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
"""UI Sidecar entrypoint for the Knowledge Compiler WebGL Graph Visualizer."""
from __future__ import annotations
import os
import sys
from pathlib import Path

_plugin_scripts = Path(os.path.abspath(__file__)).parents[2] / 'scripts'
if _plugin_scripts.is_dir() and str(_plugin_scripts) not in sys.path:
    sys.path.insert(0, str(_plugin_scripts))

import vault_graph  # noqa: E402

if __name__ == '__main__':
    port = int(os.environ.get('ANTIGRAVITY_SIDECAR_WEB_PORT', '8765'))
    vault = vault_graph.resolve_default_vault(None)
    vault_graph.serve_vault_graph(vault, port=port, sidecar_mode=True)
