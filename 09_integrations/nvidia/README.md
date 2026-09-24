# NVIDIA SkillSpector integration

AgentShield invokes the unmodified NVIDIA SkillSpector graph in a separate subprocess and Python environment. Pinned upstream version, commit and package hash are in `component-lock.json`; dependency versions are in `requirements.lock`.

Upstream: [NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector/tree/c7958a3268d9498644b22edb75d0f051bbc8cbfc), Apache-2.0. [Upstream license](https://github.com/NVIDIA/SkillSpector/blob/c7958a3268d9498644b22edb75d0f051bbc8cbfc/LICENSE). This integration does not claim NVIDIA verification, endorsement or a verified publisher signature. Installed package bytes were compared with the pinned repository's `src/skillspector` tree. Transitive packages retain their own licenses.

## Reproduce

Use an installed Python supported by upstream (3.12–3.14); this machine used 3.14.7. Run from the AgentShield project directory. `uv` installs only into the dedicated environment below.

```sh
uv venv --python 3.14 .venv-skillspector
uv pip install --python .venv-skillspector/bin/python -r 09_integrations/nvidia/requirements.lock
.venv/bin/python 09_integrations/nvidia/record_install.py
.venv/bin/python 05_skill_eval/nvidia_scan.py --skill 06_samples/vulnerable-skill
```

The recorded package hash is checked before every scan. A mismatch is an error, not an invitation to automatically trust new bytes. Reinstallation from the lock may require access to GitHub and the package index; runtime scanning does not install dependencies.

For private-model semantic analysis, configure the project's existing `config.json` and add `--with-llm`. The key is passed through subprocess stdin, not argv or inherited environment. The worker sets the upstream `openai_compatible` provider internally. The core project's original Python environment is unchanged.

## Boundary and evidence

- A bounded, symlink-free copy of the selected Skill is hashed before analysis. Scanned scripts are not executed. New reports use owner-only directories/files.
- The worker disables proxy autodetection and tracing, strips inherited provider settings, denies subprocess launches and constrains Python socket operations. Static mode denies connections; semantic mode permits only resolved addresses and port of the configured model endpoint. This is an accidental-egress guard for a trusted scanner, **not an OS sandbox** against native malicious code. Nothing in this integration runs untrusted code.
- OSV online lookups are denied by this policy. Upstream fallback/coverage limitations remain visible. `--no-llm` alone would not provide this network property.
- Upstream's `source_local_only` means that source content may not be sent to a provider. It is not a “disable external source traversal” switch. The adapter leaves it false; `use_llm` controls model analysis, the input snapshot controls locality, the direct graph call does not enable transitive CLI traversal, and the network guard blocks other destinations.
- Raw `skillspector.json` is retained byte-for-byte. Its SHA-256, upstream finding IDs, input manifest, coverage, model telemetry and I/O event counters accompany the adapted result. Original local-rule score and external engine score are separate.
- A requested model pass with zero successful calls, missing coverage, errors or partial coverage is not marked complete. Upstream `execution_successful=false` is shown as failed even when static findings are available.
- Raw reports can contain excerpts from the scanned input. Keep local originals private; inspect/redact them before external sharing. Ordinary web scans only accept the three bundled synthetic samples.

## Current product entry points

Open `/nvidia` in the local web app. Static or private-model scans produce regular report pages with an independent NVIDIA panel and raw JSON download. CLI accepts a specified local Skill directory; URL/archive inputs are intentionally outside this adapter's interface.

`10_skills/agentshield-audit` is a project-dependent Skill draft. Its syntax validation passes; official scan reports references to project/runtime files outside the Skill bundle as incomplete. Keep that limitation until packaging and Tier 3 evaluation establish the intended runtime boundary. It is not a standalone, signed or NVIDIA-Verified Skill.

## Private Qwen transport validation

`compatible_provider.py` uses the official provider extension mechanism. Its explicit HTTP clients disable proxy discovery and keepalive; this avoids cached async sockets crossing the separate event loops used by upstream graph nodes. Qwen thinking is disabled; request context budget is 8192, output cap is configured within 512–4096 (upstream may apply a lower limit), request timeout is at most 60 seconds and the overall worker limit is 240 seconds. These are request controls, not hardware capacity claims.

All three bundled samples completed with 5/5 successful model nodes after the transport fix. Previous partial/failed runs remain preserved; consult [dated acceptance results](../../01_specs/nvidia-integration-2026-09-24.md) for exact reports and limitations. Run the transport regression with `.venv-skillspector/bin/python tests/nvidia_provider.py`; it uses only a synthetic loopback HTTP server.
