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

.PHONY: test lint format check check-okf-version install install-plugin graph help

help:
	@echo "Available commands:"
	@echo "  make test               Run hermetic unit test suite"
	@echo "  make lint               Run ruff static analysis"
	@echo "  make format             Format codebase with ruff"
	@echo "  make check              Run all checks (lint + test)"
	@echo "  make check-okf-version  Check upstream GoogleCloudPlatform/open-knowledge-format SPEC.md version"
	@echo "  make graph              Launch interactive WebGL Vault Graph server on http://127.0.0.1:8765"
	@echo "  make install            Install package locally + global Antigravity plugin"
	@echo "  make install-plugin     Install/sync global plugin for Antigravity"

test:
	python3 -m unittest discover tests -v

lint:
	uvx ruff check .

format:
	uvx ruff format .

check: lint test

check-okf-version:
	python3 scripts/vault_lint.py --check-okf-upstream

graph:
	python3 scripts/vault_graph.py --serve --port 8765

install-plugin:
	python3 scripts/install_plugin.py

install: install-plugin
	pip install -e ".[extract,dev]"

