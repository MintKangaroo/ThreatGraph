# Contributing

Use Python 3.12 or later and create changes on a focused branch. Keep each pull request
small, typed, tested, and documented.

Before committing, run:

```bash
make install web-install
make check
```

Use Conventional Commits, such as `feat(api): add health endpoint` or
`test(domain): cover target rejection`. Never commit `.env`, credentials, tokens,
production data, or details of unauthorized targets. Security-sensitive changes must
include abuse cases and tests for deny-by-default behavior.
