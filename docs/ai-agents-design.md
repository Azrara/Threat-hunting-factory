# Proposed solution: two local AI agents

This document proposes the design for two AI agents built into Threat Hunting Factory, running on
open source models served locally by Ollama:

* **Agent 1, the Hypothesis Author.** Reads CTI articles, vendor reports and threat hunting write ups
  and produces new hunting hypotheses for the catalogue.
* **Agent 2, the Behavioural Analyst.** Analyses any log type and produces observations that are not
  limited to the fixed rule library, covering suspicious behaviour the rules do not describe.

Nothing here is implemented yet. This is the plan to agree on before code is written.

---

## 1. The governing principle: the model proposes, the engine verifies

A threat hunting report is evidence that a client acts on. A local 8B to 14B model will invent an
ATT&CK identifier, misquote a log line and state a false conclusion with total confidence. So the
architecture puts the model where it is strong and never where it is authoritative:

| The model is allowed to | The model is never allowed to |
|---|---|
| Read prose and extract structure | Decide that something is a confirmed compromise on its own |
| Rank, group and explain candidates the engine found | Produce a log excerpt (excerpts are always copied from the parsed corpus) |
| Draft text: description, risk, impact, recommendation | Publish a hypothesis or activate a detection rule without a human |
| Propose a field extraction spec for an unknown format | Be the only reason an observation exists at critical or high severity |

Every model output passes through a validator before it reaches the database. Every AI observation is
tagged with its origin, the model name, the prompt version and a confidence, so a reviewer can always
separate what the deterministic engine proved from what the model suggested. The existing 136 rules
stay fully deterministic, which means an audit can be reproduced byte for byte with the AI layer
switched off.

**The application must keep working with no Ollama installed.** The AI layer is a feature flag. When
the server is unreachable, hunts run exactly as they do today and the interface shows the AI panels
as unavailable rather than failing.

---

## 2. Architecture

```
                       +------------------------------------------+
   CTI article  ---->  |  Agent 1: Hypothesis Author              |
   (URL, PDF, paste)   |  extract -> ground -> map -> dedupe      |
                       +------------------+-----------------------+
                                          |  draft hypothesis (status=draft)
                                          v
                            +-------------------------+
                            |  Human review and publish |
                            +------------+--------------+
                                         |
                                         v
   Evidence archive ---> [ ingest -> parsers -> normalised events ] ---> HuntContext
                                         |
                    +--------------------+---------------------+
                    |                                          |
                    v                                          v
        [ 136 deterministic rules ]              +--------------------------------+
                    |                            | Agent 2 stage A: profiling     |
                    |                            | pure Python, no model          |
                    |                            | entity features, peer z score, |
                    |                            | sequence surprise, rarity      |
                    |                            +---------------+----------------+
                    |                                            | <= 200 candidates
                    |                                            v
                    |                            +--------------------------------+
                    |                            | Agent 2 stage B: adjudication  |
                    |                            | Ollama, batched, schema bound  |
                    |                            +---------------+----------------+
                    |                                            |
                    +--------------------+-----------------------+
                                         v
                              [ validators and guards ]
                                         v
                            Observations (origin: rule | anomaly | ai)
                                         v
                              Report, dashboard, PDF
```

Two properties matter in that picture:

1. Stage A of agent 2 produces observations **without any model at all**. Robust statistics on entity
   behaviour already answer "suspicious behaviour the rules do not describe", deterministically and
   in milliseconds. The model then adjudicates and narrates. If Ollama is down, stage A observations
   still appear, marked lower confidence.
2. The model never sees 500,000 events. Stage A reduces the corpus to a few hundred candidates with a
   feature profile and a handful of representative lines each. This is the only way the design scales.

---

## 3. Agent 1: the Hypothesis Author

### Input

Three intake paths, in order of implementation priority:

1. Pasted text or an uploaded file (markdown, txt, html, pdf). Always available, no network needed.
2. A URL fetched server side, subject to the deployment network policy, with an allowlist of known
   CTI domains configurable per tenant.
3. A watched folder or a scheduled feed (later, optional).

PDF text extraction needs `pypdf`, the only new hard dependency for this agent.

### Pipeline

```
clean -> chunk -> extract (structured) -> ground -> map to rules -> dedupe -> draft
```

**Clean.** Strip boilerplate, navigation and code fences, normalise whitespace, keep section headings
as anchors so extracted claims can cite where they came from.

**Chunk.** Sections of roughly 1,500 tokens with 150 token overlap, never splitting a table or an IOC
block. A long report becomes 10 to 60 chunks.

**Extract.** One model call per chunk, `temperature: 0`, `format` bound to a JSON schema. The schema
asks for:

```json
{
  "actors": ["..."], "malware": ["..."], "campaign": "",
  "techniques": [{"id": "T1055", "name": "", "evidence_quote": "", "platform": "windows"}],
  "behaviours": [{"summary": "", "observable_in": ["sysmon"], "evidence_quote": ""}],
  "indicators": {"domains": [], "ips": [], "hashes": [], "paths": [], "commands": []},
  "targeted_sectors": [], "confidence": "high|medium|low"
}
```

The `evidence_quote` field is mandatory on every claim. It is how grounding is enforced.

**Ground.** This is the step that makes the agent trustworthy:

* Every `evidence_quote` must appear verbatim in the source chunk. If it does not, the claim is
  dropped. This single check removes most fabrication.
* Every technique ID is validated against a local ATT&CK reference table shipped in the repository
  (`app/ai/attack_reference.json`, technique ID, name, tactics, platforms). Unknown IDs are dropped.
  A technique name that does not match its ID is corrected from the table, not from the model.
* Indicators are validated by type: IP addresses parsed with `ipaddress`, hashes matched on length
  and alphabet, domains checked for label validity.

**Map to rules.** The catalogue already links hypotheses to detections through `rule_selectors`, and
every rule carries `mitre_technique_id`. We build a technique to rule index once from `RULES_BY_ID`,
covering the 96 techniques already implemented. The agent therefore does not invent detection logic,
it **selects** existing, tested detections for the techniques it extracted. For techniques with no
rule, the draft records an explicit **detection gap**, which is valuable output in itself: it tells
the team what the library cannot see yet.

**Optional rule drafting (phase 5, off by default).** For a gap, the agent may propose a candidate
rule as declarative JSON matching the existing `Cond` and `RuleSpec` vocabulary, never as Python.
The candidate must pass: schema validation, regex compilation, the ReDoS harness already used in
`tests/test_redos.py`, and a dry run against the sample corpus showing a sane match rate. It lands in
a review queue and is never active until a human accepts it.

**Dedupe.** Embed the draft summary with `nomic-embed-text` and compare to the 33 existing hypotheses
plus pending drafts by cosine similarity. Above 0.88, the draft is attached to the existing hypothesis
as a new intelligence reference instead of creating a duplicate entry.

### Output

A `DraftHypothesis` row with the same shape as the frozen `Hypothesis` dataclass (name, family,
summary, narrative, rationale, priority, threat actors, tactics, required and optional data sources,
rule selectors, expected findings, method) plus provenance: source URL or file, per claim quotes,
model name, prompt version, extraction confidence.

Status flow: `draft -> in_review -> published` or `rejected`. Only an admin or analyst publishes.
Published drafts are merged into the catalogue as tenant scoped hypotheses so one client's
intelligence does not leak into another tenant. This requires making the catalogue tenant aware,
which is the largest structural change in this plan, because `HYPOTHESES` is a module level constant
today.

---

## 4. Agent 2: the Behavioural Analyst

### Stage A: deterministic behavioural profiling, no model

For every entity in the parsed corpus (host, user, process image, source address, destination, user
agent, container image) the profiler builds a feature vector from the normalised events:

| Family | Features |
|---|---|
| Volume | event count, events per active hour, burstiness, longest silence |
| Diversity | distinct destinations, ports, parents, children, files, cardinality ratios |
| Rarity | frequency rank of the value inside its own peer group, across the corpus |
| Timing | off hours ratio, weekend ratio, interval regularity, dominant frequency and spectral power |
| Content | Shannon entropy and normalised entropy of command lines, arguments, domains, URIs |
| Volumetrics | bytes in and out, in to out ratio, Gini concentration, Benford first digit fit |
| Structure | parent to child lineage rarity, transition surprise of the event type sequence |

Almost all of this already exists in `app/engine/stats_math.py`: `shannon_entropy`,
`normalised_entropy`, `dga_score`, `beacon_score`, `dominant_frequency`, `interval_regularity`,
`modified_zscores`, `rarity_scores`, `benford_chi_square`, `gini_coefficient`, `percentile`. The new
pieces are the entity profiler, peer grouping and two scorers:

* **Peer group robust outliers.** Compare an entity only to entities of the same kind, using modified
  z scores over the median absolute deviation. This is the fix already applied to `stat-volume-outlier`,
  generalised to every feature. Scoring within peer groups is what prevents the classic false positive
  of comparing a domain controller to a laptop.
* **Sequence surprise.** Build a first order Markov transition matrix over per entity event type
  sequences for the corpus, then score each entity by the mean negative log probability of its own
  transitions. This catches "the right events in the wrong order", which no fixed rule expresses. It
  is cheap, explainable and entirely deterministic.

An entity becomes a **candidate** when its combined anomaly score exceeds a percentile threshold, or
when at least three independent features are outliers at once. Agreement across independent features
is the quality signal, not the magnitude of any single one.

Stage A already emits observations on its own, with `origin: anomaly`, capped at `info` to `medium`
severity, text generated from templates rather than from a model.

### Stage B: adjudication and narration by the model

Each candidate is packaged as a compact prompt: the entity, its outlier features with values and peer
medians, related rule findings if any, and up to 8 representative raw log lines referenced by
identifier. Candidates are batched, roughly 5 per call, to amortise prompt processing.

The model returns, per candidate, a schema bound object:

```json
{
  "candidate_id": "...",
  "verdict": "suspicious | benign | inconclusive",
  "confidence": "high | medium | low",
  "rationale": "why, in two or three sentences",
  "attack_hypothesis": "what an attacker doing this would be doing",
  "mitre_technique_id": "T1071.001 or empty",
  "evidence_ids": ["ev-0012", "ev-0019"],
  "risk": "", "impact": "", "recommendation": "",
  "benign_explanation": "the most likely innocent explanation"
}
```

The `benign_explanation` field is deliberate. Asking the model to argue the other side measurably
reduces the rate at which it labels routine administration as an attack.

### Validators between the model and the database

1. **Evidence citation check.** `evidence_ids` must resolve to lines that were actually parsed. The
   stored excerpt is then copied from the corpus, never from the model output. A fabricated quote
   cannot reach the report, which protects the requirement that every observation carries the original
   log extract.
2. **Technique whitelist.** Same ATT&CK table as agent 1.
3. **Severity ceiling.** An observation whose only support is the model is capped at `medium`. It can
   exceed that only when a deterministic rule finding or a stage A outlier corroborates it.
4. **Text hygiene.** Length limits, no markdown injection into the PDF, house style enforced,
   no em dashes.
5. **Benign verdicts are kept, not discarded**, and shown in a collapsed "reviewed and dismissed"
   section. Showing what was examined and cleared is what makes a hunt report credible.

### Unknown log formats: the model writes a parser, not a verdict

The engine has 15 parsers and falls back to `TextParser` when a file matches nothing. That fallback is
the practical limit of "any log type that exists on this earth". Proposal: when a file lands on the
text fallback with low confidence, sample 30 lines, ask the model for a field extraction spec:

```json
{"format_name": "", "line_regex": "", "field_map": {"1": "user.name", "2": "source.ip"},
 "timestamp_field": "", "timestamp_format": ""}
```

Then validate it, and only then use it:

* the regex compiles, contains bounded quantifiers only, and passes the ReDoS harness;
* it extracts on at least 80 percent of a held out sample of lines the model never saw;
* extracted values type check against the target ECS style field (an IP field must parse as an IP).

A spec that passes is cached as a `LearnedParser` for that tenant and reused on later hunts with no
further model calls. This is the strongest use of the model in the whole design, because the output
is a program that is verified by execution rather than an opinion that has to be trusted.

### Attack story correlation

After all observations exist, one final call takes the observation titles, entities, techniques and
timestamps (not the raw logs) and produces a kill chain narrative: ordered phases, the entities
involved, the ATT&CK tactics, and what the analyst should collect next. This becomes the executive
summary of the PDF. It only ever references observations that exist, checked by identifier.

---

## 5. Models and hardware

| Role | Default model | Small machine | Workstation |
|---|---|---|---|
| Extraction, adjudication, narration | `qwen2.5:14b-instruct-q4_K_M` | `llama3.1:8b-instruct-q4_K_M` | `qwen2.5:32b-instruct-q4_K_M` or `gpt-oss:20b` |
| Embeddings for dedupe and clustering | `nomic-embed-text` | `nomic-embed-text` | `bge-m3` for multilingual CTI |

Selection criteria: strong JSON schema adherence under `format`, a context window of at least 16k, a
permissive licence, and availability as a standard Ollama tag. Qwen 2.5 14B is the recommended default
because it holds structured output better than Llama 3.1 8B at this task while still fitting in 12 GB
of VRAM at Q4.

Indicative throughput per hunt, 60 model calls, roughly 1,200 prompt tokens and 400 output tokens each:

| Hardware | 8B Q4 | 14B Q4 |
|---|---|---|
| CPU only, 8 cores | 25 to 40 minutes | 60 to 100 minutes |
| RTX 3060 12 GB | 3 to 5 minutes | 6 to 9 minutes |
| RTX 4090 or A100 | under 2 minutes | 2 to 3 minutes |

This is why **the AI layer never blocks the hunt**. The deterministic report is complete and viewable
first, then AI observations stream in and the report updates. On CPU only deployments, the interface
says so and offers to run the enrichment on demand rather than automatically.

All inference is local. No evidence and no client log ever leaves the tenant, which is the reason for
choosing Ollama over a hosted API and should be stated explicitly in the report footer.

---

## 6. Changes to the existing codebase

### New package

```
app/ai/
  client.py           Ollama HTTP client: chat, embeddings, schema bound output, timeouts, retries
  config.py           models, endpoints, budgets, feature flags
  schemas.py          pydantic models for every structured output
  guards.py           grounding, ATT&CK whitelist, ReDoS check, injection stripping, text hygiene
  budget.py           context budgeting, candidate sampling, batching
  attack_reference.json
  prompts/            versioned templates, one file per task, prompt_version recorded per call
  hypothesis_agent.py Agent 1
  analyst_agent.py    Agent 2 stage B
  profiles.py         Agent 2 stage A, pure Python, no model
  learned_parsers.py  unknown format specs
  correlate.py        attack story
```

### Data model

New tables: `CtiSource`, `DraftHypothesis`, `TenantHypothesis`, `LearnedParser`, `AiCall`
(model, prompt version, token counts, latency, outcome, for cost and audit).

New columns on `Observation`: `origin` (`rule`, `anomaly`, `ai`), `ai_confidence`, `ai_rationale`,
`benign_explanation`, `model_name`, `prompt_version`.

New columns on `Hunt`: `ai_enabled`, `ai_status`, `ai_observation_count`.

Since the schema is created by `Base.metadata.create_all`, a small explicit migration step is needed
for existing databases. Adding columns to SQLite is cheap, but it must be written and tested rather
than assumed.

### API

```
GET  /api/ai/status                     model availability, which models, degraded reasons
POST /api/cti/sources                   upload or paste an article, returns a job
GET  /api/cti/sources/{id}              extraction progress and result
GET  /api/hypotheses/drafts             review queue for the tenant
POST /api/hypotheses/drafts/{id}/publish
POST /api/hypotheses/drafts/{id}/reject
POST /api/hunts/{id}/ai-analysis        run or rerun the AI layer on a completed hunt
GET  /api/hunts/{id}/ai-analysis        status and results
```

The hunt creation payload gains `ai_analysis: bool`.

### Interface

* A new **Threat Intel** page: paste or upload an article, watch the extraction, review the draft
  hypotheses with the source quote beside every extracted claim, publish or reject.
* The report page gains an **AI insights** section, visually separated from rule findings, every card
  badged with its origin and confidence, with the benign explanation shown inline and a
  "reviewed and dismissed" group underneath.
* A status chip in the header: model name and availability.
* The dashboard gains AI coverage statistics: drafts pending review, AI observations confirmed or
  dismissed by analysts, detection gaps found.

The PDF marks AI observations with the same distinction and carries a standing note that they were
produced by a local model and require analyst validation.

---

## 7. Safety

**Prompt injection is the central threat, because log content is attacker controlled.** An attacker
who can write to a log file can write text designed to steer the model. Mitigations:

* Log content is never placed in the system prompt, only in a delimited data block with an explicit
  instruction that it is data to analyse and never instructions to follow.
* Control characters stripped, excerpt length capped, delimiters escaped in the data.
* The model has no tools, no function calling and no network. It cannot act, only return JSON.
* Output is schema bound and validated. An injected instruction cannot produce a field that the schema
  does not allow.
* No model output has a side effect without a human: no auto publish, no auto rule activation, no
  auto severity above medium.
* A dedicated adversarial test suite, described below.

**Hallucination** is handled by grounding: verbatim quote checks, an ATT&CK whitelist, evidence
identifiers resolved against the real corpus, and excerpts copied from the corpus rather than from the
model.

**Reproducibility.** `temperature: 0`, a fixed seed, and the model name plus prompt version recorded
on every AI observation. A report can be regenerated and defended. The deterministic layer is
unaffected by any of this.

---

## 8. Test strategy

The project rule is that everything is tested before it advances, and an AI feature is where that is
easiest to abandon and most important to keep.

1. **A fake transport.** `FakeOllama` replays recorded fixtures. Every piece of agent logic, prompt
   building, parsing, grounding, validation, batching, error handling, is tested offline and
   deterministically. This is the bulk of the new tests and it runs in CI with no GPU.
2. **A golden CTI set.** A dozen public reports with hand labelled expected techniques and actors.
   Measure extraction precision and recall, assert no regression. Stored as fixtures, not fetched.
3. **Adversarial injection suite.** Log lines carrying injection payloads ("ignore previous
   instructions", fake JSON, fake system blocks, unicode direction marks). Assert that the system
   behaviour is unchanged and the guards reject anything malformed.
4. **Anti fabrication property test.** For any model output, assert every stored excerpt exists byte
   for byte in the parsed corpus and every technique ID exists in the reference table. Run against
   randomised and deliberately malicious model outputs.
5. **Stage A determinism tests.** Same corpus, same profiles, same candidates, every time. Plus
   planted anomaly tests: inject a beaconing host, a rare lineage, an off hours burst into a benign
   corpus and assert each is surfaced.
6. **Learned parser tests.** Assert that a spec which fails the extraction rate, the type checks or
   the ReDoS harness is rejected, using hand written bad specs.
7. **Live smoke test** marked `@pytest.mark.ollama`, skipped automatically when no server responds,
   so the suite stays green everywhere while still being runnable against a real model.
8. **Degradation tests.** Ollama absent, timing out, returning malformed JSON, returning an empty
   body, returning a 500. In every case the hunt completes and the report is correct.

---

## 9. Delivery phases

Each phase is independently useful, independently testable and leaves the application working with no
Ollama installed.

| Phase | Content | Value on its own |
|---|---|---|
| 0 | `app/ai/client.py`, config, feature flag, `/api/ai/status`, `FakeOllama` harness, header chip | Infrastructure, nothing user visible yet |
| 1 | Agent 2 stage A: entity profiler, peer outliers, sequence surprise, anomaly observations | Observations beyond fixed rules, with no model at all |
| 2 | Agent 2 stage B: adjudication, narration, guards, report AI section | The analyst agent as requested |
| 3 | Agent 1: intake, extraction, grounding, rule mapping, dedupe, review and publish UI | The hypothesis agent as requested |
| 4 | Learned parsers for unknown formats | Real coverage of arbitrary log types |
| 5 | Attack story correlation, PDF executive summary, candidate rule drafting | Report quality and library growth |

Phase 1 is deliberately first. It delivers the "not limited to fixed rules" requirement immediately,
deterministically, and it also builds the candidate reduction that phase 2 depends on. Starting with
phase 2 instead would mean sending raw logs to a model, which does not scale.

---

## 10. Honest limits

* A 14B model quantised to 4 bits is not an analyst. It is good at structure extraction and at writing,
  acceptable at ranking, and unreliable at judgement. The design reflects that, and the severity
  ceiling on model only observations is not negotiable.
* CPU only inference is slow enough to change the user experience. The asynchronous design handles it,
  but a deployment without a GPU should expect the AI layer to be an on demand action rather than an
  automatic one.
* Making the hypothesis catalogue tenant scoped touches the catalogue, the API and the interface. It
  is the one structurally invasive change here and should be estimated as such.
* Model licences differ. Qwen 2.5 and Llama 3.1 both carry conditions that a consulting deployment
  should review before shipping to a client.
* Stage A will produce false positives on small corpora, because robust statistics need population.
  A minimum entity and event count per peer group is required before outlier scoring runs at all.

---

## 11. Decisions needed before implementation

1. Default model: `qwen2.5:14b` as proposed, or `llama3.1:8b` to guarantee it runs on any laptop.
2. Target hardware for the reference deployment, which sets whether AI enrichment is automatic or on
   demand.
3. Whether published hypotheses are tenant scoped (recommended) or global to the platform.
4. Whether candidate rule drafting in phase 5 is in scope at all, or whether detection gaps should
   simply be reported for a human to implement.
5. Whether URL fetching for CTI intake is permitted in the target environment, or whether intake is
   upload and paste only.
