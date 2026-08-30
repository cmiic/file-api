# Contributing to File API

Thanks for taking the time to contribute. This document covers how to get the project running, what CI expects, and how changes get merged.

## Code of Conduct

This project is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating you are expected to uphold it. Report unacceptable behaviour to <c@miic.at>.

## Reporting bugs and requesting features

Open an [issue](https://github.com/cmiic/file-api/issues/new/choose) using one of the templates. Please do **not** open a public issue for a security vulnerability — see [SECURITY.md](SECURITY.md) instead.

## Development

```bash
cd app && go vet ./... && go test ./...
cd pdf-sidecar && go vet ./...
```

To run the whole stack locally, see the development section of the [README](README.md).

Go vetting and the markdown linter run in CI.

## Making a change

`main` is protected. All changes go through a pull request:

1. Branch from `main`.
2. Make the change, with tests where behaviour changes.
3. Open a pull request describing what changed and why.
4. CI must be green — the required checks are **Lint, Build, Test**.
5. Your branch must be up to date with `main` before merging. Because required checks are strict, merging one pull request puts the others behind; use the "Update branch" button to bring yours forward.

Copilot reviews every pull request automatically. Address or reply to what it raises; it is often right, but not always — say so when it is not.

## Commit messages

Use a short imperative subject with a conventional prefix, matching the existing history:

```text
feat: bound media processing resources
fix: distinguish worker timeout failures
docs: record third-party signature terms
chore(deps): bump ruff from 0.16.3 to 0.16.4
```

Explain *why* in the body when the reason is not obvious from the diff.

## Licensing of contributions

By contributing, you agree that your contributions are licensed under the MIT License, the same licence as this project. See [LICENSE](LICENSE).
