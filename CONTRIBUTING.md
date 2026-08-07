# Contributing

## Running the tests

```bash
make test          # all unit tests with race detector
make lint          # golangci-lint
make fuzz          # 3x60s fuzz runs (takes ~3 minutes)
```

## Validating example policies

```bash
make build
for p in examples/*/mcpguard.yaml; do ./mcpguard validate --policy "$p" --offline; done
```

## Commit messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

- `feat(scope): description` — new feature
- `fix(scope): description` — bug fix
- `docs: description` — documentation only
- `test: description` — tests only
- `chore: description` — build, tooling, CI

## Pull requests

- Link to an issue
- Single concern per PR
- Tests included for any behavioural change
- `make lint && make test` must pass
