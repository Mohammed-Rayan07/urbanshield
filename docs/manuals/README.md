# Start here (everyone, 15 minutes)

You'll build one part of UrbanShield with your coding agent. Your manual tells the agent exactly what
to build; the tests tell it when it's done. You review, run, commit and push.

| Part | Manual | Branch | Owner |
|---|---|---|---|
| A — City twin + simulator (+ audit log after h6) | [A_city_sim.md](A_city_sim.md) | `a/city-sim` | _name_ |
| B — Optimiser + baselines + evaluation | [B_optimizer.md](B_optimizer.md) | `b/optimizer` | _name_ |
| C — Agents + guardrails + API (integrator) | [C_agents.md](C_agents.md) | `c/agents` | Rayan |
| D — Dashboard + demo video | [D_frontend.md](D_frontend.md) | `d/frontend` | _name_ |

## 1. Install (Windows, PowerShell)

```powershell
winget install --id Git.Git -e
winget install --id astral-sh.uv -e          # Python package manager (installs Python 3.12 for you)
winget install --id OpenJS.NodeJS.LTS -e     # only needed for part D
winget install --id GitHub.cli -e
```

Close and reopen the terminal, then:

```powershell
gh auth login                                # GitHub.com → HTTPS → login with browser
gh repo clone Mohammed-Rayan07/urbanshield
cd urbanshield
git switch -c a/city-sim                     # use YOUR branch name from the table
cd backend; uv sync; uv run pytest           # should say "N passed, M skipped"
```

## 2. Give your coding agent its brief

Open your coding agent **in the repo folder** and paste this as the first message
(replace the manual name):

```text
You are building one part of a hackathon project. First read AGENTS.md, then read
docs/manuals/A_city_sim.md completely, then backend/src/urbanshield/schemas.py.
Follow the manual's tasks in order. After each task: run the tests named in that task,
run `uv run ruff check . --fix && uv run ruff format .` in backend/, and show me the
test output. Do not edit files outside "You own". Do not edit schemas.py or types.ts.
Do not skip, delete or weaken tests. Start with task 1.
```

## 3. The loop

1. Agent does one task → you run the tests yourself → they pass.
2. `git add -A; git commit -m "sim: <what you did>"; git push -u origin <your-branch>`
3. At each **merge window** (h6, h10, h14, h16) open or update your PR: `gh pr create --fill`.
   Rayan reviews and merges. Then `git pull origin main` to pick up everyone else's work.

**Push from your own GitHub account.** Judges read the commit history; everyone's work should show.

## 4. When stuck

- A test fails and you don't understand why: paste the full failure into your agent and ask it to
  explain *before* fixing.
- You think a contract (`schemas.py`) is wrong: **don't change it**. Message Rayan with the field and why.
- Stuck more than 20 minutes: message the team group with the error and what you tried.
