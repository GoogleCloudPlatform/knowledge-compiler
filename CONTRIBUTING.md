# Contributing to Knowledge Compiler

Thank you for your interest in contributing to **Knowledge Compiler** (`https://github.com/GoogleCloudPlatform/knowledge-compiler`)!

## Contributor License Agreement (CLA)

Contributions to this project must be accompanied by a [Contributor License Agreement](https://cla.developers.google.com/) (CLA). You (or your employer) retain the copyright to your contribution; this simply gives Google permission to use and redistribute your contributions as part of the project.

If you or your employer have already signed the Google CLA (even if it was for a different project), you probably do not need to sign it again. Visit <https://cla.developers.google.com/> to see your current agreements or to sign a new one.

## Code Reviews

All submissions, including submissions by project members, require review. We use GitHub pull requests for this purpose. Consult [GitHub Help](https://help.github.com/articles/about-pull-requests/) for more information on using pull requests.

## Code of Conduct

This project follows [Google's Open Source Community Guidelines](https://opensource.google/conduct/).

## Development Setup

```bash
git clone https://github.com/GoogleCloudPlatform/knowledge-compiler.git
cd knowledge-compiler
python3 -m unittest discover -s tests -p "test_*.py" -v
```

## Pull Request Checklist

1. **Unit Tests**: Ensure all tests in `tests/` pass (`python3 -m unittest discover -s tests -p "test_*.py" -v`).
2. **Apache 2.0 License Headers**: Include the standard 13-line `# Copyright 2026 Google LLC` + `Licensed under the Apache License, Version 2.0` header on all new `.py`, `.js`, and `.yml` source files.
3. **Zero Private Identifiers**: Never commit customer names, internal URLs, or personal workstation paths. Run `python3 scripts/sanitize_check.py --strict` before opening a PR.

## Disclaimer

This is not an officially supported Google product. Eligibility for the [Google Open Source Software Vulnerability Rewards Program](https://bughunters.google.com/open-source-security) is determined by the Google OSS VRP Rules.
