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
- **Simulated arena**: rules mode needs neither Docker nor a model; agent mode requires models. Nine attack/defense scenarios (public Wi-Fi, malicious Skill, lateral movement, phishing & session theft, Web/API privilege escalation, supply-chain poisoning, AI agent prompt injection, guest device / office appliance access, cloud key & storage bucket); red and blue models decide on their own, and tools only mutate the virtual scenario — no real packets. Tune the defense policy and compare both attack outcomes and normal-business impact. See [arena scenario spec](01_specs/extended-arena-2026-09-26.md) and [live drill scenarios spec](01_specs/live-drill-scenarios-2026-09-29.md).
- **Agent chat**: hit AGENT at the bottom right — a ReAct loop acting step by step: read reports, audit skills, run commands (read-only whitelist runs directly, everything else asks you one by one), start the live range, delete reports (confirmation gate).
- **Plain-language explanations**: unfamiliar with security jargon? Read the model-generated explanations; want to dig deeper? Inspect the rules, evidence and raw reports.

NVIDIA review uses unmodified SkillSpector 2.12.0, with results shown separately from local checks. Install instructions: [NVIDIA integration guide](09_integrations/nvidia/README.md); completed verifications: [integration log](01_specs/nvidia-integration-2026-09-24.md).

## Live drills (requires local Docker)

The regular arena is a simulation. **Live drills** move the duel into a Docker-isolated network where red team really fires packets and blue team really changes protection settings — the entry point is the "🔴 Docker Live Range" card on the arena page; click "Let the Agent guide me" to have the agent walk you through:

- **Requirements**: Docker (no Kali installation needed — the attacker box is the official Kali arm64 container image). The red-team container plus a deliberately vulnerable target (OWASP Juice Shop) run inside an internal network with no egress; attacks cannot reach your router or the internet.
- **How it plays**: the red-team model invokes real in-container tools (nmap/sqlmap/curl etc.); every attack action shows the full command and executes only after your confirmation. Blue team's moves are enabling/disabling the WAF in front of the target (red team cannot route around the WAF at the network level). Wins are judged by HTTP probes against the target, not model self-assessment. One click destroys all containers afterwards; every command and output is persisted.
- **Named scenario scripts**: three one-click drills with objective oracles — SQL injection session hijack (`sqli_session`), XSS encoded WAF bypass (`xss_encoded_bypass`), broken access-control user enumeration (`bac_enumeration`). The range card's scenario picker (or `livelab.py run <scenario>`) demos the attack, flips the WAF, re-fires, judges from the target's own records, and restores the WAF to `block`. See [live drill scenarios spec](01_specs/live-drill-scenarios-2026-09-29.md).
- **Boundaries**: network and web-application layers only. Wi-Fi RF scenarios (MITM, deauth) are out — Apple Silicon's built-in Wi-Fi has no monitor mode; that needs an external USB adapter plus a full Kali VM, a possible future option. The target ships with real vulnerabilities and must only ever run inside the isolated network, never exposed to any reachable network; red-team munitions are allowed only against in-range targets — if isolation fails, the lab refuses to start.
- **Legality**: only the targets inside your own containers may be engaged. Testing any system you don't own or lack written authorization for is illegal; this project neither provides nor assists such capability.

### Using the current UI

1. Start local Docker, configure and test a model connection in Settings, then open the arena.
2. Choose from the shared scenario list. **SQL injection and XSS encoding-bypass Docker scenarios appear first.**
3. Click **“Let the Agent guide me”**. The Agent checks or starts the range and plans each step from tool feedback. Review the complete command, then confirm, cancel, or enter your own response.
4. Refresh the range status to check containers and WAF mode. Use **“Stop and clean up range”** to finish; closing the page does not stop containers.

| Scenario | Docker coverage |
| --- | --- |
| SQL injection / session hijacking | Compare login requests with the WAF enabled and disabled |
| XSS encoding bypass | Compare literal and encoded input filtering; an accepted request does not prove browser-side XSS execution |
| Web / API authorization | Cross-user enumeration only; other cases remain synthetic |
| AI agent injection, malicious Skills and other scenarios | Synthetic simulation only; Docker guidance is disabled with an explanation |

There is one Agent guidance entry. The fixed-script run button has been removed; backend scripts remain for reproduction and regression checks. The synthetic rules demo needs no model; Agent guidance and red/blue model decisions require a model service.

When a confirmation question has no model-supplied choices, the UI supplies confirm/cancel buttons. Open questions have a text field and submit button. An unparseable Ask stops the turn instead of repeatedly retrying. After updating code and restarting the WebUI, reload the page and start a new conversation; sessions do not survive a server restart. Existing videos and GIFs show earlier recordings, so their button layout may differ from the current UI.

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

**StepFun (阶跃星辰)** is a supported cloud option: set `base_url` to `https://api.stepfun.com/v1` and `model` to a current Step model ID (e.g. `step-3.7-flash`; see [StepFun quick start](https://platform.stepfun.com/docs/zh/quickstart/overview)), with the key created in the [StepFun console](https://platform.stepfun.com/interface-key).

### Local inference on DGX Spark (or the ASUS Ascent GX10): Qwen3.8-27B / Qwen3.8-Flash-Next

Run inference on **DGX Spark and connect AgentShield through a local OpenAI-compatible endpoint** for agent guidance, red/blue decisions and report explanations. The model server and Docker range are separate processes; stopping a range does not unload the model.

[NVIDIA DGX Spark](https://www.nvidia.com/en-us/products/workstations/dgx-spark/) has 128 GB of unified memory shared by the OS, weights, KV cache and Docker containers. Start with 27B, then try Flash-Next; load only one model at a time.

**Drop-in alternative — ASUS Ascent GX10**: an OEM build of the same NVIDIA GB10 Grace Blackwell platform — same 20-core Arm CPU (10× Cortex-X925 + 10× Cortex-A725), 1 PFLOP FP4 tensor performance, 128 GB LPDDR5x unified memory, and it ships NVIDIA DGX OS ([ASUS tech specs](https://www.asus.com/networking-iot-servers/desktop-ai-supercomputer/ultra-small-ai-supercomputers/asus-ascent-gx10/techspec/)). Everything in this section applies to the GX10 unchanged; only storage (1 TB / 2 TB / 4 TB options) and I/O details differ.

| Model | Starting configuration | Selection notes |
| --- | --- | --- |
| [Qwen3.8-27B](https://huggingface.co/Qwen/Qwen3.8-27B) | [Unsloth GGUF](https://huggingface.co/unsloth/Qwen3.8-27B-GGUF) `UD-Q4_K_M` | A dense 27B model; the initial option to leave room for other services |
| [Qwen3.8-Flash-Next](https://huggingface.co/Qwen/Qwen3.8-Flash-Next) | [Unsloth GGUF](https://huggingface.co/unsloth/Qwen3.8-Flash-Next-GGUF) `UD-Q3_K_XL`, experimental | 125B MoE with 6B active, plus 51B n-gram embeddings and 4B MTP. Do not size it as a 6B model. This quantization is about 90 GB on disk, with additional runtime memory required |

These are third-party Unsloth quantizations, not original Qwen weights. Flash-Next `UD-Q4_K_XL` is about 111 GB on disk, leaving little room on one Spark, so this example starts with a smaller quantization and 8K context. Validate capacity, quality and speed on your hardware; “Flash” is not a measured AgentShield speed claim.

**1. Build llama.cpp with CUDA on Spark.** First check that `nvidia-smi` and `nvcc --version` work with the installed NVIDIA driver and CUDA Toolkit. Run the following in Spark's Linux terminal; downloading source and weights requires network access. See the [llama.cpp build instructions](https://github.com/ggml-org/llama.cpp/blob/master/docs/build.md).

```bash
sudo apt-get update
sudo apt-get install -y git cmake build-essential libssl-dev libcurl4-openssl-dev
mkdir -p "$HOME/llm"
cd "$HOME/llm"
git clone https://github.com/ggml-org/llama.cpp.git
cd llama.cpp
cmake -B build -DGGML_CUDA=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j 4 --target llama-server
# Record the revision; use a recent version supporting the model architecture
git rev-parse HEAD
```

**2. Start one model.** Choose one command below, from the `llama.cpp` directory. The first launch downloads weights; wait for successful loading. Options are documented in the [llama-server reference](https://github.com/ggml-org/llama.cpp/tree/master/tools/server).

```bash
# Option A: Qwen3.8-27B
./build/bin/llama-server \
  -hf unsloth/Qwen3.8-27B-GGUF:UD-Q4_K_M \
  --alias agent-shield-local --host 127.0.0.1 --port 8000 \
  --api-key spark-local -ngl 99 -c 16384 -np 1 \
  --jinja --chat-template-kwargs '{"enable_thinking":false}'
```

```bash
# Option B: Qwen3.8-Flash-Next (stop option A with Ctrl+C first)
./build/bin/llama-server \
  -hf unsloth/Qwen3.8-Flash-Next-GGUF:UD-Q3_K_XL \
  --alias agent-shield-local --host 127.0.0.1 --port 8000 \
  --api-key spark-local -ngl 99 -c 8192 -np 1 \
  --jinja --chat-template-kwargs '{"enable_thinking":false}'
```

Non-thinking mode is an integration starting point so reasoning does not consume the limited output budget; this is not an optimal sampling recipe or capability benchmark. For unknown architecture/template errors, rebuild a llama.cpp version supporting the model. If memory runs out, reduce context or return to 27B. CPU offloading does not add physical memory on Spark's shared-memory system.

**3. Check the endpoint and connect AgentShield.** In another Spark terminal:

```bash
curl --fail http://127.0.0.1:8000/v1/models \
  -H 'Authorization: Bearer spark-local'
curl --fail http://127.0.0.1:8000/v1/chat/completions \
  -H 'Authorization: Bearer spark-local' -H 'Content-Type: application/json' \
  -d '{"model":"agent-shield-local","messages":[{"role":"user","content":"Introduce yourself in one sentence."}],"max_tokens":256}'
```

Check for nonempty `choices[0].message.content`. Enter the following values in AgentShield Settings, or merge this `cloud` object into your existing `config.json`, keeping other configuration:

```json
{
  "cloud": {
    "base_url": "http://127.0.0.1:8000/v1",
    "api_key": "spark-local",
    "model": "agent-shield-local",
    "max_tokens": 4096
  }
}
```

`cloud` is the project's configuration name for OpenAI-compatible endpoints; inference here remains local to Spark. **Do not leave the key empty**: the current client requires a nonempty key to enable this path. The example key matches the server flag and is for loopback use. `OPENAI_BASE_URL`, `OPENAI_API_KEY` and `OPENAI_MODEL`, when set, override the main model's file configuration. Let both arena roles inherit the main model: they share the server but keep separate conversation contexts.

If AgentShield runs on a Mac/PC and the model runs on Spark, keep this SSH tunnel running on the Mac/PC, replacing the user and hostname:

```bash
ssh -N -L 8000:127.0.0.1:8000 spark-user@spark-host
```

Keep AgentShield's URL as `http://127.0.0.1:8000/v1`; the model port need not be public. Start AgentShield using the quick start, then test the model connection in Settings, an agent conversation and a red/blue drill. When Spark only supplies inference, system checks and Docker tools still execute on the AgentShield host. System checks currently primarily target macOS.

To stop: press `Ctrl+C` in the model terminal to release model memory, `Ctrl+C` in the tunnel terminal to close forwarding, and use “Stop and clean up range” for Docker. For hardware validation, record the llama.cpp commit, quantization revision, context length, time to first token, generation speed and peak memory.

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
.venv/bin/python 08_arena/livelab.py scenario            # list the named scenario scripts
.venv/bin/python 08_arena/livelab.py run sqli_session    # demo + judge one scenario
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

Install, run and output locations: [integration guide](09_integrations/README.md).

## Roadmap

Next steps, roughly in order:

1. **More rule-arena scenarios** — RAG knowledge-base poisoning and container privilege-boundary scenarios, extending the existing declarative scenario framework.
2. **More live drill scripts** — an nmap reconnaissance script and a sqlmap automation script as named one-click scenarios alongside the current three.
3. **OpenShell gateway testing** — complete the isolated-execution gateway so dynamic Skill review runs against real sandboxes.
4. **Adaptive presentation** — automatic recognition of the user's expertise level instead of the current manual depth toggle.

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
