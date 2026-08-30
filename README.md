# flakectl

**Agentic CI flake categorization and analysis for Podman CI.**

A working proof-of-concept built alongside my CNCF/LFX mentorship proposal for
[Podman — Agentic CI Flake Categorization and Analysis][issue] (#1963, Term 3 2026).

Given a failing CI log, `flakectl` answers two questions:

1. is this a **real failure** or a **flake**, and
2. if it is a flake, **which kind**?

```console
$ flakectl analyze samples/*.log --history samples/history.json

TEST                                          VERDICT    CATEGORY             CONF  FINGERPRINT       SEEN  NEW
---------------------------------------------------------------------------------------------------------------
Podman healthcheck run [It] podman healthch…  flake      race_timing          0.78  6a1cfc950ff997af     1  yes
Podman kube play [It] podman kube play --va…  real       real_regression      0.87  20839585a792698f     1  yes
Podman pod create [It] podman pod create --…  flake      test_pollution       0.88  a54628f6b0498d44     1  yes
Podman run [It] podman run with --systemd=a…  real       environment_drift    0.88  2985d7802312a51a     1  yes
Podman pull [It] podman pull from docker wi…  flake      infrastructure       0.95  71c7451399a94d05     1  yes
podman run with slirp4netns assigns correct…  flake      network_timeout      0.90  008e9cd3b4a393f0     1  yes
```

Everything above runs **offline** — no API key, no network, no model.

[issue]: https://github.com/containers/podman/issues

---

## The problem

Podman's CI is not short of signal — it's drowning in it. A single failing `int`
job produces tens of megabytes of Ginkgo output, and somewhere inside is one line
that tells you whether the PR is broken or the runner just lost its network for
two seconds. Right now a human maintainer has to go and find that line.

The failure modes are qualitatively different from each other and cannot be told
apart by a regex over the string `FAIL`:

- a registry returning 429 is **infrastructure**;
- `pasta` not having finished starting is **network/timing**;
- a spec that polls with a fixed sleep instead of `Eventually` is a **test race**;
- a container leaked by an earlier spec is **test pollution**, and the spec that
  reports the failure is usually innocent;
- a runner image bumping `crun` is **environment drift**, which looks exactly like
  a regression until you notice the code didn't change;
- and some failures are **actual regressions**, which must never be silently
  absorbed into "flake".

## The design, in one line

**Deterministic-first, abstention-friendly.** Cheap, reviewable logic resolves
everything it can before a model is ever invoked, and the categorizer is required
to answer `unknown` rather than guess.

That constraint drives everything else. A tool that auto-files issues and is wrong
30% of the time is worse than no tool: maintainers will mute it inside a week.
Precision matters more than recall here, and the system has to be able to say
*I don't know*.

## Pipeline

```
                 ┌──────────── Pillar 1: ingest ────────────┐
   CI log ──────▶│ failure-window slicer  (hard byte cap)   │
   JUnit XML ───▶│ structured artifact    (preferred path)  │
                 └────────────────────┬─────────────────────┘
                                      ▼
                 ┌──────── Pillar 2: deterministic ─────────┐
                 │ normalize   strip timestamps, IDs, ports │
                 │ fingerprint hash(signature + test id)    │
                 │ detect      attempt N fail → N+1 pass    │
                 │ rules       maintainer-owned YAML        │
                 └────────────────────┬─────────────────────┘
                                      │ only what's left
                                      ▼
                 ┌──────── Pillar 3: agentic analysis ──────┐
                 │ provider    rules · anthropic ·          │
                 │             gemini · ollama              │
                 │ tools       log / source / history /     │
                 │             issues / recent changes      │
                 │ budget      max calls, bytes, lines      │
                 │ gates       schema → regression → conf.  │
                 └────────────────────┬─────────────────────┘
                                      ▼
                 ┌──────── Pillar 4: reporting ─────────────┐
                 │ table · JSON · weekly markdown digest    │
                 │ dry-run always · per-run caps · marked   │
                 │ agent-generated with model + prompt ver. │
                 └──────────────────────────────────────────┘
```

### Pillar 1 — ingest

Keeps only the failure window: the `[FAILED]` block, the `Summarizing N Failures`
section, bounded context. A **hard byte cap is enforced here**, not left to a later
stage to respect — a 40MB log becomes a handful of ~4KB records. JUnit/Ginkgo XML
is the *preferred* path (`flakectl analyze --junit`); raw log scraping is the
fallback, not the default.

### Pillar 2 — the deterministic pre-filter

The pillar that matters most and is easiest to under-scope.

- **Normalize**: strip timestamps, container/image IDs, UUIDs, `IP:port`, `/tmp`
  paths, PIDs, hex addresses, durations, Ginkgo node numbers. What's left is the
  *shape* of the failure.
- **Fingerprint** = `sha256(normalised signature + test identity)[:16]`. Both halves
  matter: the signature alone merges "container name already in use" across
  unrelated specs; the test identity alone merges one spec's distinct failure modes.
- **Detect**: a job that failed on attempt N and passed on attempt N+1 at the same
  SHA is non-deterministic *by definition*. That call needs no model. A second
  signal compares against `main` at the same base commit — it never proves
  flakiness, so it only records whether the change under test can be responsible.
- **Rules**: a maintainer-editable YAML ruleset ([`flakectl/data/rules.yaml`](flakectl/data/rules.yaml))
  catches the well-understood classes for free. Adding a rule is a review, not a release.

Only unseen fingerprints reach a model, and a known fingerprint reuses its cached
analysis — so cost is **O(distinct failure modes)**, not O(failures), and the same
flake gets the same explanation in week three that it got in week one.

### Pillar 3 — the agentic categorizer

The agent starts with the sliced failure and a set of tools it can call for more:

| Tool | What it answers |
| --- | --- |
| `get_log_slice` | more of the retained log, on demand |
| `get_test_source` | the failing spec at the commit that failed — this is what distinguishes *"the test waits with a fixed sleep"* from *"the product has a genuine race"* |
| `search_history` | how often this fingerprint has been seen, and on which jobs |
| `search_issues` | is there already an open flake issue for it |
| `recent_changes` | did a recent commit touch the code under test |

Budgets — max tool calls, max total bytes into context, max lines per call — are
enforced **in the tool layer, not asked of the model**. A model that ignores an
instruction to be frugal is a bug report; a model that *cannot* exceed a budget is
a design.

Output is schema-validated ([`flakectl/schema.py`](flakectl/schema.py)); invalid
output gets one bounded retry, then abstains. Four gates run in order: **cache →
schema → regression guard → confidence gate**. The regression guard is the one I'd
point at: if the categorizer claims a regression but a re-run passed at the same
commit, the measured evidence wins and the failure goes to a human.

Four providers sit behind one interface — `rules` (offline, the default),
`anthropic` (hosted Claude, tool-calling), `gemini` (hosted Google, function
calling), `ollama` (local). Same orchestrator, same schema, same taxonomy, same
eval, so comparing them is a number rather than an argument.

Adding `gemini` was the test of whether that boundary is real: it needed one new
file and two lines in a registry. Nothing in the orchestrator, tool layer, budget,
schema or eval changed. The only vendor-specific wrinkle is that Gemini takes an
OpenAPI subset rather than full JSON Schema, so `to_gemini_schema()` strips the
keywords it rejects on the way out — the shared schema stays canonical.

### Pillar 4 — reporting

A per-failure table, a JSON report, and a weekly markdown digest that calls out
**newly-appeared signatures separately** — a brand-new flake usually means
something changed recently, which makes it the most actionable line on the page.

Every artifact is stamped agent-generated with its provider, model and prompt
version. **Everything is dry-run**: the digest renders the issue bodies it *would*
file (with the fingerprint marker that makes filing idempotent) and the PR comment
it *would* post. `flakectl` has no GitHub write path at all, and `--no-dry-run` is
refused with an explanation.

## Taxonomy

Maintainer-owned YAML ([`flakectl/data/taxonomy.yaml`](flakectl/data/taxonomy.yaml)),
deliberately not hardcoded. Editing a description changes how failures are
classified, because the categorizer is handed these descriptions at analysis time.

| Category | Meaning |
| --- | --- |
| `infrastructure` | Runner eviction, OOM, disk pressure, registry 429/5xx |
| `network_timeout` | DNS, socket timeouts, pasta/netavark/slirp4netns startup |
| `race_timing` | Fixed sleep instead of `Eventually`; healthcheck not converged |
| `test_pollution` | Leaked container, shared image store, parallel node interference |
| `environment_drift` | Runner image bump — crun, kernel, systemd, conmon |
| `real_regression` | **Escalate.** Never absorbed into a flake bucket |
| `unknown` | **Abstain.** Routed to a human digest; no issue, no PR comment |

Two flags carry behaviour: `escalate` (never treat as a flake) and `abstain` (this
is the answer when the tool doesn't know).

## Running it

```bash
make install     # venv + editable install
make test        # 284 tests
make demo        # the whole pipeline, offline, end to end
make eval        # score the categorizer against the labelled corpus
```

Offline is the default everywhere:

```bash
flakectl ingest  samples/int_fedora41_race_timing.log
flakectl analyze samples/*.log --junit samples/junit_int_remote.xml \
                 --history samples/history.json --source-root samples/src
flakectl report  --input report.json
flakectl eval
```

`flake-triage` is installed as an alias, so `flake-triage analyze ...` works too.

### With a model

The hosted and local paths are opt-in and change nothing else about the pipeline:

```bash
# hosted Claude, tool-calling
pip install -e ".[llm]"
export ANTHROPIC_API_KEY=...          # read from the env, never stored or logged
flakectl analyze samples/*.log --online --provider anthropic \
                 --source-root samples/src --issues samples/issues.json

# hosted Gemini, function calling (no extra dependency — stdlib HTTP)
export GEMINI_API_KEY=...
flakectl analyze samples/*.log --online --provider gemini --model gemini-3.6-flash

# or locally, with nothing leaving the machine:
ollama serve
flakectl analyze samples/*.log --online --provider ollama --model llama3.1
```

Keys are read from the environment at request time and are never written to a
report, a log line, or the store.

## Evaluation

`make eval` scores the categorizer against 34 hand-labelled failures
([`eval/labels.jsonl`](eval/labels.jsonl)). Numbers below are the current offline
ruleset — reproduce them with `flakectl eval`:

| Category | Support | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: |
| `infrastructure` | 6 | 1.00 | 0.83 | 0.91 |
| `network_timeout` | 6 | 1.00 | 0.83 | 0.91 |
| `race_timing` | 6 | 1.00 | 0.83 | 0.91 |
| `test_pollution` | 6 | 1.00 | 0.67 | 0.80 |
| `environment_drift` | 5 | 1.00 | 0.80 | 0.89 |
| `real_regression` | 5 | 0.71 | 1.00 | 0.83 |
| **macro avg** | **34** | | | **0.87** |

```
accuracy                     82.4%
accuracy when it answered    93.3%   (30 of 34)
abstention rate              11.8%   (4 routed to a human)

missed-regression rate        0.0%   regression reported as a flake — must be 0
false-regression rate         6.9%   flake reported as a regression — noise
```

The two regression rates are the ones that decide whether auto-filing could ever
be switched on:

- **Missed regressions** (a real regression called a flake) is the failure that
  costs maintainer trust fastest. `flakectl eval` **exits non-zero** if this is
  ever above zero, so it fails a run rather than being a line in a table nobody reads.
- **False regressions** (a flake called a regression) is currently 6.9%, and the
  eval names the two cases: when no rule matches and the failure reproduced on
  every attempt, the offline heuristic falls back to `real_regression`. Both
  misses are cases where a maintainer would want the agent, not the ruleset. That
  is the honest argument for Pillar 3 existing at all.

Abstention is scored as a recall miss, never as a wrong answer, because declining
is the designed behaviour. The corpus deliberately contains failures no rule
matches, so these numbers are not a ruleset grading its own homework.

## How this maps to the proposal

| Proposal | Here |
| --- | --- |
| Pillar 1 — ingestion, log slicing, byte caps | [`parser.py`](flakectl/parser.py), [`junit.py`](flakectl/junit.py) |
| Pillar 2 — normalise, fingerprint, dedup, rules, re-run detection | [`normalize.py`](flakectl/normalize.py), [`fingerprint.py`](flakectl/fingerprint.py), [`store.py`](flakectl/store.py), [`rules.py`](flakectl/rules.py), [`detector.py`](flakectl/detector.py) |
| Pillar 3 — provider abstraction, tools, schema, confidence gate | [`providers/`](flakectl/providers/), [`tools.py`](flakectl/tools.py), [`schema.py`](flakectl/schema.py), [`agent.py`](flakectl/agent.py) |
| Pillar 4 — weekly report, dedup'd issue filing, PR comment, guardrails | [`report.py`](flakectl/report.py) |
| Eval harness with real numbers | [`evaluate.py`](flakectl/evaluate.py), [`eval/`](eval/) |
| SQLite: file-based, zero-ops, inspectable with `sqlite3` | [`store.py`](flakectl/store.py) — stdlib only |
| Taxonomy as maintainer-owned YAML, not hardcoded | [`data/taxonomy.yaml`](flakectl/data/taxonomy.yaml) |
| Abstention as a first-class outcome | the confidence gate in [`agent.py`](flakectl/agent.py) |

**Where this deviates from the proposal, and why:**

- **Python, not Go.** §4.1 of the proposal argues for a Go core with a clean
  adapter boundary at the model layer, and I still think that's right for the real
  thing — it matches the repo, `go-github` is mature, and it ships as one static
  binary. This prototype is Python because the point was to de-risk the *design*
  quickly, not to pick the language. The adapter boundary the proposal describes
  is implemented here ([`providers/base.py`](flakectl/providers/base.py)), so the
  port is mechanical rather than a rewrite. Language is still a week-1 mentor call.
- **`resource` is folded into `infrastructure`** and **`test_bug` is split into
  `race_timing` and `test_pollution`**, matching the proposal's taxonomy rather
  than a generic one. A leaked container and a fixed sleep have different
  mitigations and different owners, so they are different categories.

## Limitations, honestly

This is a recent proof-of-concept exploring the problem, not a finished product.

- **No live GitHub Actions client.** Pillar 1's discovery layer — ETag conditional
  requests, persisted cursors, backoff with jitter, the ~1,000 req/hour budget — is
  designed in the proposal and *not* built here. `flakectl` reads log files and
  JUnit artifacts; job/OS metadata comes from `history.json`, which is shaped like
  what the API returns. This is the largest gap between the prototype and the plan.
- **The corpus is synthetic.** Six sample logs and 34 labelled snippets, written to
  be realistic but not harvested from real runs. The proposal budgets real time for
  hand-labelling ~150 historical Podman failures; without that, every accuracy
  number here is indicative rather than trustworthy.
- **The eval measures the ruleset, not the agent.** The offline provider is what
  these numbers score. The agent path *has* been exercised against a live model
  (Gemini 3.6 Flash: it classified the healthcheck sample `race_timing` at 0.95,
  cited verbatim log lines, and independently recommended `Eventually` over the
  fixed sleep — which is the actual bug in `samples/src`). But that is one failure,
  not a corpus. `flakectl eval --online --provider gemini` is one command away;
  the free tier's 5-request cap makes a 34-example run impractical, and each agent
  turn costs a request, so a tool loop exhausts it in a single analysis.
- **The Claude path has never made a live call.** It is exercised only against a
  stubbed client. The loop mechanics, budget accounting, schema validation and
  error paths are verified; prompt quality and real latency and cost are not.
- **No issue filing or PR commenting.** Only the dry-run rendering of both. That is
  deliberate — the proposal gates auto-filing per category on the eval numbers
  justifying it, and the numbers above do not yet justify it for any category.
- **`test_pollution` recall is 0.67**, the weakest category. Attribution is the
  genuinely hard problem the proposal names: the spec that reports the failure is
  often not the spec that caused it, and neither the ruleset nor a single-failure
  agent view can see the polluter. That needs cross-spec ordering analysis.
- **The Ollama adapter is single-shot**, not tool-calling. Smaller local models
  handle a constrained JSON answer far more reliably than a multi-turn tool loop,
  and shipping the version that works seemed better than claiming parity.
- **No quarantine recommendations, trend dashboard, or auto-generated fixes.**
  Those are stretch goals in the proposal and are not attempted here.

### Next steps, in the order I'd do them

1. The real Actions API client with the budget discipline from Pillar 1 — this is
   the thing that turns a demo into a tool.
2. Hand-label real Podman failures and re-run the eval, so the numbers mean something.
3. Benchmark a local model against a hosted one on that corpus and report actual
   cost and latency, as the proposal commits to.
4. Cross-spec attribution for `test_pollution`, the weakest category.
5. Issue filing behind a per-category flag, enabled only where the eval justifies it.

## Development

```
flakectl/
  parser.py normalize.py fingerprint.py store.py detector.py rules.py
  taxonomy.py tools.py schema.py agent.py pipeline.py report.py evaluate.py
  providers/  base.py rules_provider.py anthropic_provider.py gemini_provider.py ollama_provider.py
  data/       taxonomy.yaml rules.yaml     # maintainer-owned, reviewed as YAML
samples/      6 CI logs · JUnit artifact · history.json · test sources
eval/         labels.jsonl · run.py
tests/        284 tests, no network, no API key
```

Python 3.11+. Runtime dependencies are `typer` and `PyYAML`; `anthropic` is an
optional extra (`pip install -e ".[llm]"`) and the offline path never imports it.
SQLite is from the standard library.

---

*Built by [Rohit Kumawat](https://github.com/ROKUMATE) as a concrete realization of
my LFX mentorship proposal. Written with AI assistance (Claude); the design,
taxonomy and evaluation methodology are from the proposal, and every number in this
README is reproducible with `make eval`.*
