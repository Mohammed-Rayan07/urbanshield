# Integrator checklist (Rayan)

## Merge windows

| Window | Expect | Gate |
|---|---|---|
| **h6** | A: graphs + generator + simulate · B: common + baselines + greedy · D: shell + components | `test_city`, `test_sim` green |
| **h10** | B: MILP + ablations · D: map + plans screen · C: adapter, tools, Sentinel | **CP1:** run `compare` on the demo city — CVaR beats CVSS-first and BFS-only on test set? If not, tune A's demo structure *now* |
| **h14** | A: audit log + Auditor · B: evaluation · D: agents screen · C: Analyst, Planner, Red-Team | end-to-end run in `mock` mode |
| **h16** | everything wired; **CP2:** Flow A live once → record replay traces → rough video cut | feature freeze at h19 |

## PR review (5 minutes each)

1. `gh pr checkout <n>`; CI green? `uv run pytest` / `npm run build` locally.
2. Diff touches only the owner's paths? No edits to contracts or tests (other than un-skipping)?
3. Read the public functions: signatures unchanged, docstrings true, no dead code, no prints, no secrets.
4. Determinism: seeds threaded through, no global random.
5. Merge with **squash off** (keep their commits for attribution): `gh pr merge <n> --merge`.

## Contract changes

Only you edit `schemas.py` / `types.ts`. Change both in one commit on `main`, announce in the group,
everyone `git pull origin main`.

## Before submission (h19–h23)

- `ecc:security-reviewer` agent + `/code-review` on the full diff; fix findings.
- `webapp-testing` e2e of Flow A and Judge Mode.
- README: video link, screenshots, EVALS headline numbers. `docker compose up --build` works from a clean clone.
- Make sure the repo is public and the final commit is before the deadline.
