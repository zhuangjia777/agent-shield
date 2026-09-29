# AgentShield

**English** | [简体中文](README.zh-CN.md)

![AgentShield](docs/assets/readme-cover.svg)

**An AI security agent that actually launches the attacks itself.** It starts by auditing and scoring your machine for privacy and vulnerabilities, then moves the red-vs-blue duel into a real Docker-isolated network: a Kali attacker box sends real packets, the WAF really blocks and really allows, and the outcome is judged by the target's own records. Runs 100% locally, MIT licensed.

## Video: live red–blue drill & Agent design

https://github.com/user-attachments/assets/7d859898-fcee-42a4-bb74-403a42390e1d

**[Download video (2:42, Chinese narration and subtitles)](docs/assets/agent-shield-live-agent-v2.mp4)** · [Subtitle file](docs/assets/agent-shield-live-agent-v2.zh-CN.srt)

A replay of an existing Docker drill: the same attack is blocked with the WAF enabled, succeeds with protection disabled, and is blocked again after protection is restored. The walkthrough explains the ReAct tool loop, human confirmation, isolation checks, and target-based judging. In live mode, one Agent coordinates the red-team tools and blue-team WAF.

## WebUI overview

![AgentShield WebUI: report cards, health scores, navigation and Agent entry](docs/assets/webui-overview.png)

## Live Docker drill

![Live Docker drill recording: a SQL injection blocked by the WAF, the same payload landing after blue team turns the WAF off, and the judge confirming the win from the target's own records](docs/assets/live-arena-demo.gif)

The GIF above is a real run recording from an AgentShield live drill (model thinking pauses compressed): the red-team container attacks an admin login with SQL injection — 403-blocked while the WAF is on, normal traffic unaffected; after blue team mistakenly turns the WAF off, **the very same payload** obtains admin login credentials; the judge reads the target's own API to confirm `loginAdminChallenge` — model self-assessment is not trusted. When the drill ends, one click destroys every container, and all commands and outputs are persisted to disk.

## Let the Agent guide me

![Actual WebUI recording: click Let the Agent guide me, inspect tool feedback, then confirm or cancel the proposed attack command](docs/assets/agent-guided-demo.gif)

An actual run through the Docker live-range entry: the Agent checks the existing range, proposes a command, receives `need_confirm`, and asks the user to confirm or cancel. The recording stops at confirmation; no attack was executed for this capture. Model waiting time is shortened.

## Arena WebUI: attack, defense and retest

![Arena WebUI replay: attack events, defensive changes, retesting and before/after metrics](docs/assets/webui-arena-demo.gif)

This clip shows the **fixed-flow rules simulation**, with red/blue event feeds and before/after metrics. It uses synthetic events and sends no real attack packets; the Docker drill above demonstrates real execution.

[User guide (Chinese)](README.zh-CN.md) · [Install & run](#install--run)

## What it does

- **Live drills (real attacks)**: spin up a training range inside a Docker-isolated network — a Kali container as red team, a toggleable WAF as blue team, OWASP Juice Shop as the vulnerable target. The agent walks you through the fight step by step: every attack action shows the full command first and runs only after you confirm; after blue team enables/disables protection, red team re-fires the same attack, so defense effectiveness is compared on the spot. See [Live drills](#live-drills-requires-local-docker).
- **Machine checkup**: checks system security settings, optional LAN probing, outputs a 0–100 health score with per-item fix advice. System checks are currently mainly adapted for macOS.
- **Skill auditing**: local rules find security risks in Agent Skills; NVIDIA SkillSpector can be installed as a complementary review. Reports list findings, supporting evidence and scan scope.
- **Simulated arena**: the lightweight mode needing neither Docker nor models. Six attack/defense scenarios (public Wi-Fi, malicious Skill, lateral movement, phishing & session theft, Web/API privilege escalation, supply-chain poisoning); red and blue models decide on their own, and tools only mutate the virtual scenario — no real packets. Tune the defense policy and compare both attack outcomes and normal-business impact. See [arena scenario spec](01_specs/extended-arena-2026-09-26.md).
- **Agent chat**: hit AGENT at the bottom right — a ReAct loop acting step by step: read reports, audit skills, run commands (read-only whitelist runs directly, everything else asks you one by one), start the live range, delete reports (confirmation gate).
- **Plain-language explanations**: unfamiliar with security jargon? Read the model-generated explanations; want to dig deeper? Inspect the rules, evidence and raw reports.

NVIDIA review uses unmodified SkillSpector 2.12.0, with results shown separately from local checks. Install instructions: [NVIDIA integration guide](09_integrations/nvidia/README.md); completed verifications: [integration log](01_specs/nvidia-integration-2026-09-24.md).

## Live drills (requires local Docker)

The regular arena is a simulation. **Live drills** move the duel into a Docker-isolated network where red team really fires packets and blue team really changes protection settings — the entry point is the "🔴 Docker Live Range" card on the arena page; click "Let the Agent guide me" to have the agent walk you through:

- **Requirements**: Docker (no Kali installation needed — the attacker box is the official Kali arm64 container image). The red-team container plus a deliberately vulnerable target (OWASP Juice Shop) run inside an internal network with no egress; attacks cannot reach your router or the internet.
- **How it plays**: the red-team model invokes real in-container tools (nmap/sqlmap/curl etc.); every attack action shows the full command and executes only after your confirmation. Blue team's moves are enabling/disabling the WAF in front of the target (red team cannot route around the WAF at the network level). Wins are judged by HTTP probes against the target, not model self-assessment. One click destroys all containers afterwards; every command and output is persisted.
- **Boundaries (the ugly truth first)**: network and web-application layers only. Wi-Fi RF scenarios (MITM, deauth) are out — Apple Silicon's built-in Wi-Fi has no monitor mode; that needs an external USB adapter plus a full Kali VM, a possible future option. The target ships with real vulnerabilities and must only ever run inside the isolated network, never exposed to any reachable network; red-team munitions are allowed only against in-range targets — if isolation fails, the lab refuses to start.
- **Legality**: only the targets inside your own containers may be engaged. Testing any system you don't own or lack written authorization for is illegal; this project neither provides nor assists such capability.

## Scope & limitations

- Results depend on rule and test-case coverage; no findings does not mean no risk.
- Use test samples for drills — never production accounts or real secrets; use network checks only on devices you own or are authorized to test.
- Skill static scans and template reports work offline (`--no-ai`, `--no-narrative`); model-backed analysis needs the respective service.

## Install & run

Steps below use macOS; system checkup is mainly adapted for macOS. The main program uses only the Python standard library — the web UI, local rule scans and arena simulation need no extra Python dependencies and no DGX Spark.

### 1. Get the project

Prepare Git and Python 3.11, and make sure `python3 --version` points to it. In your chosen directory:

```bash
git clone https://github.com/zhuangjia777/agent-shield.git
cd agent-shield
python3 -m venv .venv
```

If you already cloned it, just `cd agent-shield` — no need to clone again.

### 2. Configure the model

```bash
# First run: configure the LLM (copy config.json.example to config.json)
test -f config.json || cp config.json.example config.json  # keeps an existing config
```

Edit the three fields under `cloud` in `config.json`:

| Field | Value |
| --- | --- |
| `base_url` | OpenAI-compatible endpoint URL, usually ends with `/v1` |
| `api_key` | access key for that endpoint |
| `model` | model name provided by the service |

You can also fill this in via the web UI's Settings after startup. Rule scans and scripted demos need no model; red/blue agents, AI explanations and narrative reports do. Both arena sides inherit the main model by default, and each can be configured with its own endpoint, model and key in Settings. `config.json` is Git-ignored — never put real keys in the example config.

### 3. Start the web UI

In the project directory:

```bash
.venv/bin/python 04_web/app.py --open
```

Your browser opens [AgentShield](http://127.0.0.1:8787). Keep the terminal running while in use; `Ctrl+C` stops the server. Next time, just run the same command from the project directory.

If port 8787 is taken:

```bash
.venv/bin/python 04_web/app.py --port 8788 --open
```

#### Stopping the program

Press **Control + C (Ctrl+C)** in the terminal that started it. Closing the browser tab alone does not quit the program.

If you can't find that terminal, see which process holds the default port:

```bash
lsof -nP -iTCP:8787 -sTCP:LISTEN
```

Once confirmed it's AgentShield:

```bash
lsof -tiTCP:8787 -sTCP:LISTEN | xargs kill
```

If you started on another port, replace `8787` accordingly. Run the start command again next time.

### 4. Optional: NVIDIA SkillSpector

Install this only if you want the NVIDIA Skill security review. It lives in its own Python environment; the commands below require `uv` and run from the project directory:

```bash
uv venv --python 3.14 .venv-skillspector
uv pip install --python .venv-skillspector/bin/python \
  -r 09_integrations/nvidia/requirements.lock
.venv/bin/python 09_integrations/nvidia/record_install.py
```

Installation downloads dependencies over the network. The last command verifies component contents and records the install path. Afterwards open [NVIDIA Skill review](http://127.0.0.1:8787/nvidia). More details: [integration install & reproduction guide](09_integrations/nvidia/README.md).

## Command line

All commands run from the project directory:

```bash
# Evaluate a Skill with local rules only, no model
.venv/bin/python 02_scan/cmd_scan.py --skill 06_samples/vulnerable-skill --no-ai

# Generate JSON/Markdown/HTML reports with model-written narratives
.venv/bin/python 03_ai/report.py --input reports/eval_vulnerable-skill/results.json

# Offline report with template narratives
.venv/bin/python 03_ai/report.py --input reports/eval_vulnerable-skill/results.json --no-narrative

# Run the benchmark suite
.venv/bin/python tests/run_evals.py
```

The live range can also be driven without the web UI:

```bash
.venv/bin/python 08_arena/livelab.py start   # bring up the range (runs network-isolation checks)
.venv/bin/python 08_arena/livelab.py status  # container & WAF status
.venv/bin/python 08_arena/livelab.py stop    # tear everything down
```

## How to read a report

The local health score starts at 100 and loses points per finding: −25 critical, −12 high, −5 medium, −2 low, floor 0. The score is computed by rules; the model explains it but never changes it.

Each finding's risk value is computed as below, then bucketed into a severity:

```text
risk = impact × exploitability × evidence_confidence × exposure
```

Impact and exploitability range 1–5 (higher = easier to exploit); evidence confidence is 0.5, 0.75 or 1.0; exposure is 0.5, 1.0 or 1.5. See [findings.py](02_scan/findings.py) for the exact math.

NVIDIA SkillSpector scores go the other way — higher means riskier — and never add to the local health score. With model analysis enabled it may affect NVIDIA's risk score.

## Test status

Local rules currently hit all 5 expected checks on the three sample Skills, with no high-severity false positives on the benign and hardened samples. This covers those samples only — not all 30 evaluation cases. Details: [BENCHMARK.md](BENCHMARK.md). The NVIDIA engine's coverage and runtime are logged separately in the [integration log](01_specs/nvidia-integration-2026-09-24.md).

## Agents & NVIDIA integration

The arena page uses red/blue agents by default: each side has its own context, the model picks tools from observations and keeps acting on results. Red team can observe and attempt targets; blue team can view alerts, enable protections and check business traffic. Up to 4 decisions per side; tools only mutate the virtual scenario, and the judge is rule-based. A no-model scripted demo remains available.

- **Provenance verification** is wired into Skill review: the official OMS verifier with pinned NVIDIA trust certificates, showing unsigned / failed / passed separately. Passing verification still requires security checks.
- **The OpenShell execution adapter** provides scoped tools, strict file/network policies and operation logs. Real isolated execution needs an available gateway; gateway testing is not yet complete.
- **SkillEvaluator Tier 3** uses the official tool with four with/without-Skill task pairs. Data-format validation passes; effectiveness conclusions must come from complete experiment results on both groups; failed runs never produce a lift score.

Install, run and output locations: [integration guide](09_integrations/README.md). DGX Spark migration on real hardware is still pending; an existing private model endpoint works meanwhile.

## Project layout

```text
01_specs/        architecture, feature specs, verification logs
02_scan/         scan entry, system & network checks, scoring rules
03_ai/           model calls, result explanations, report generation
04_web/          local web UI
05_skill_eval/   Skill check rules & NVIDIA scan entry
06_samples/      vulnerable / hardened / benign sample Skills
07_evals/        evaluation cases and expected results
08_arena/        arena simulation + live range control (livelab.py, waf.py)
09_integrations/ NVIDIA component versions, locks, runtime adapters
10_skills/       AgentShield audit-skill drafts (effect comparison pending)
docs/assets/     README cover and doc images
reports/         locally generated reports, not committed
tests/           automated checks and evaluation scripts
config.json      model endpoints, keys, Ollama config, not committed
BENCHMARK.md     test results and pending evaluation items
```

## License

MIT, see [LICENSE](LICENSE).
