# github-core-clone

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/abduljunior425/github-core-clone/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/abduljunior425/github-core-clone/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

A single-file clone of GitHub's core, built for the [Make a GitHub core clone bounty](https://make.fun/bounty/github-core-clone-01) on make.fun. One Python file, standard library only, one process, no external git binary.

## What it implements

- **Git object store** — blob, tree, commit, and tag objects, plus packfile read and write with OFS and REF delta resolution, including thin packs.
- **Smart HTTP** — upload-pack v2 and v0, receive-pack v0, so real `git push`, `git clone`, and `git fetch` work against it.
- **REST v3** — repositories, branches, commits, contents, labels, issues, and pull requests, including squash merge and three-way conflict detection.
- **GraphQL** — a hand-written tokenizer, parser, and executor, `__type` introspection, opaque global ids, cursor pagination, and batch queries.
- **MCP** — the modern 2026-07-28 `server/discover` flow plus the legacy `initialize` flow, with 6 canonical tools.
- **Deterministic** — every timestamp comes from a fixed epoch; no clock, randomness, or UUIDs anywhere in the server.

## Run it

```sh
python3 main.py
```

The server listens on port 18080. `/healthz` answers when it is up.

## Verification

The kit's sealed suite (120 checks: git, repos, issues, pulls, protocol, GraphQL, MCP) passes **120/120** in 5 consecutive full runs. With the timed performance workloads the totals were **922** and **966**, both above the house baseline of about 900. End-to-end checks with the real git CLI pass too: `git push`, `git clone`, `git clone --depth 1`, and incremental `git fetch --deepen=2`, with `git fsck` clean and file contents byte-identical.

## Files

- `main.py` — the whole server, 130,436 bytes.
- `LICENSE` — MIT.
