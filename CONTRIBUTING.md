# Contributing

Use Python 3.12 or later and create changes on a focused branch. Keep each pull request
small, typed, tested, and documented.

## Branch strategy

- `main` always contains an executable, stable version.
- `develop` integrates the next release.
- `feat/<feature-name>` contains one feature branched from `develop`.
- `fix/<problem-name>` contains one bug fix branched from `develop`.
- `docs/<document-name>` contains documentation-only changes branched from `develop`.

Open pull requests from focused branches into `develop`. Promote a tested release from `develop`
to `main`; do not commit feature work directly to either shared branch.

Before committing, run:

```bash
make install web-install
make check
```

Use Conventional Commits, such as `feat(api): add health endpoint` or
`test(domain): cover target rejection`. Never commit `.env`, credentials, tokens,
production data, or details of unauthorized targets. Security-sensitive changes must
include abuse cases and tests for deny-by-default behavior.
