"""共享 LLM 客户端：云端 vLLM(OpenAI 兼容, 支持流式) + Ollama 兜底。

config.json 每个请求时读取（改完设置立即生效，无需重启）。
"""
from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load_config() -> dict:
    f = ROOT / "config.json"
    if f.exists():
        try:
            return json.loads(f.read_text())
        except Exception:
            return {}
    return {}


def save_config(cfg: dict) -> None:
    path = ROOT / "config.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        os.fchmod(fh.fileno(), 0o600)
        fh.write(json.dumps(cfg, ensure_ascii=False, indent=2))


def cloud_cfg() -> dict:
    c = load_config().get("cloud", {})
    return {
        "base_url": os.environ.get("OPENAI_BASE_URL") or c.get("base_url", ""),
        "api_key": os.environ.get("OPENAI_API_KEY") or c.get("api_key", ""),
        "model": os.environ.get("OPENAI_MODEL") or c.get("model", "gpt-4o-mini"),
        "max_tokens": c.get("max_tokens", 2500),
    }


def ollama_cfg() -> dict:
    c = load_config().get("ollama", {})
    return {
        "url": os.environ.get("OLLAMA_URL") or c.get("url", "http://127.0.0.1:11434"),
        "model": os.environ.get("OLLAMA_MODEL") or c.get("model", "qwen2.5:3b"),
    }


def _post(url: str, payload: dict, headers: dict | None = None, timeout: int = 120) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _best_content(message: dict) -> str:
    for k in ("content", "reasoning", "reasoning_content"):
        if message.get(k):
            return message[k]
    return ""


# ---------- 非流式 ----------

def chat(messages: list[dict], temperature: float = 0.2) -> tuple[str, str]:
    """返回 (engine, text)：云端优先，Ollama 兜底，都失败抛异常。"""
    errs = []
    c = cloud_cfg()
    if c["api_key"]:
        try:
            resp = _post(c["base_url"].rstrip("/") + "/chat/completions", {
                "model": c["model"], "temperature": temperature,
                "max_tokens": c["max_tokens"], "messages": messages,
            }, headers={"Authorization": f"Bearer {c['api_key']}"}, timeout=300)
            text = _best_content(resp["choices"][0].get("message") or {})
            if text:
                return "cloud", text
            errs.append("cloud: 空回复")
        except Exception as e:
            errs.append(f"cloud: {e}")
    o = ollama_cfg()
    try:
        resp = _post(o["url"] + "/api/chat", {
            "model": o["model"], "stream": False,
            "options": {"temperature": temperature, "num_predict": 2500},
            "messages": messages,
        }, timeout=600)
        text = (resp.get("message") or {}).get("content", "")
        if text:
            return "ollama", text
        errs.append("ollama: 空回复")
    except Exception as e:
        errs.append(f"ollama: {e}")
    raise RuntimeError("; ".join(errs) or "无可用 LLM 后端")


# ---------- 流式 ----------

def ollama_model_ok(cfg_model: str) -> bool:
    """本机 ollama 里是否装了目标模型（避免 404 model not found 裸抛）。"""
    o = ollama_cfg()
    if o["model"] != cfg_model:
        return False
    try:
        with urllib.request.urlopen(o["url"] + "/api/tags", timeout=5) as r:
            names = {m.get("name", "") for m in json.loads(r.read().decode()).get("models", [])}
        return cfg_model in names or any(n.startswith(cfg_model) for n in names)
    except Exception:
        return False


def _cloud_stream(messages, temperature, enable_thinking=False, timeout=600):
    """云流式：真流式逐块 yield (kind, text)，失败原地抛异常。"""
    c = cloud_cfg()
    payload = {
        "model": c["model"], "stream": True, "temperature": temperature,
        "max_tokens": c["max_tokens"], "messages": messages,
        "chat_template_kwargs": {"enable_thinking": bool(enable_thinking)},
    }
    req = urllib.request.Request(
        c["base_url"].rstrip("/") + "/chat/completions", data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {c['api_key']}"})
    got = False
    with urllib.request.urlopen(req, timeout=timeout) as r:
        for raw in r:
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("data:"):
                continue
            body = line[5:].strip()
            if body == "[DONE]":
                break
            try:
                d = json.loads(body)
            except Exception:
                continue
            choices = d.get("choices") or [{}]
            delta = choices[0].get("delta") or {}
            for key, kind in (("reasoning", "reasoning"),
                              ("reasoning_content", "reasoning"),
                              ("content", "content")):
                if delta.get(key):
                    got = True
                    yield kind, delta[key]
    if not got:
        raise RuntimeError("cloud: 流式零回复（检查 model 名 / max_tokens）")


def chat_stream(messages: list[dict], temperature: float = 0.2,
                enable_thinking: bool = False):
    """逐块流式 yield (kind, text)：kind ∈ "content" | "reasoning"。
    云端真流式 → 失败自动落 Ollama → 都挂抛出带全部原因的异常。
    enable_thinking=False（默认）让 Qwen3 关闭思考，正文秒吐，流式 UX 好。"""
    c = cloud_cfg()
    if c["api_key"]:
        try:
            yield from _cloud_stream(messages, temperature, enable_thinking)
            return
        except Exception as e:
            errs = [f"cloud: {e}"]
    else:
        errs = ["cloud: 未配置"]
    o = ollama_cfg()
    if ollama_model_ok(o["model"]):
        try:
            data = json.dumps({
                "model": o["model"], "stream": True,
                "options": {"temperature": temperature, "num_predict": 2500},
                "messages": messages,
            }).encode()
            req = urllib.request.Request(o["url"] + "/api/chat", data=data,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=600) as r:
                for raw in r:
                    line = raw.decode("utf-8", "replace").strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                    except Exception:
                        continue
                    piece = (d.get("message") or {}).get("content")
                    if piece:
                        yield "content", piece
            return
        except Exception as e:
            errs.append(f"ollama: {e}")
    else:
        errs.append(f"ollama: 未装模型 {o['model']}（跳过兜底）")
    raise RuntimeError("; ".join(errs) or "无可用 LLM 后端")
