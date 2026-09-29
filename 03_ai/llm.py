"""共享 LLM 客户端：云端 vLLM(OpenAI 兼容, 支持流式) + Ollama 兜底。

config.json 每个请求时读取（改完设置立即生效，无需重启）。
"""
from __future__ import annotations

import json
import os
import urllib.request
from urllib.parse import urlsplit
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


def cloud_cfg(config: dict | None = None) -> dict:
    c = (load_config() if config is None else config).get("cloud", {})
    return {
        "base_url": os.environ.get("OPENAI_BASE_URL") or c.get("base_url", ""),
        "api_key": os.environ.get("OPENAI_API_KEY") or c.get("api_key", ""),
        "model": os.environ.get("OPENAI_MODEL") or c.get("model", "gpt-4o-mini"),
        "max_tokens": c.get("max_tokens", 2500),
    }



def role_cloud_cfg(role: str, config: dict | None = None, main: dict | None = None) -> dict:
    """Resolve one role without changing global configuration or sharing override keys."""
    if role not in ("black", "red"):
        raise ValueError("未知的攻防角色。")
    cfg = load_config() if config is None else config
    own = cfg.get("arena_models", {}).get(role, {})
    if own.get("inherit_main", True):
        return dict(cloud_cfg(cfg) if main is None else main)
    return {"base_url": own.get("base_url", ""), "api_key": own.get("api_key", ""),
            "model": own.get("model", ""), "max_tokens": own.get("max_tokens", 2500)}


def public_config(config: dict) -> dict:
    cfg = json.loads(json.dumps(config))
    cfg.setdefault("cloud", {})
    roles = cfg.setdefault("arena_models", {})
    for role in ("black", "red"):
        roles.setdefault(role, {}).setdefault("inherit_main", True)
    for entry in [cfg["cloud"], roles["black"], roles["red"]]:
        key = entry.pop("api_key", "")
        entry.pop("api_key_masked", None)
        entry["api_key_set"] = bool(key)
        if key:
            entry["api_key_masked"] = "已保存"
    return cfg


def merge_config(current: dict, updates: dict) -> dict:
    """Merge settings. Empty key inputs preserve only the same backend's stored key."""
    if not isinstance(updates, dict):
        raise ValueError("设置格式不正确。")
    cfg = json.loads(json.dumps(current))
    for name in ("cloud", "ollama"):
        if isinstance(updates.get(name), dict):
            patch = {k:v for k,v in updates[name].items() if k not in ("api_key_masked", "api_key_set")}
            if name == "cloud" and not patch.get("api_key"):
                patch.pop("api_key", None)
            cfg.setdefault(name, {}).update(patch)
    if "arena_models" not in updates:
        return cfg
    roles = updates["arena_models"]
    if not isinstance(roles, dict) or set(roles) - {"black", "red"}:
        raise ValueError("仅支持蓝队与红队模型配置。")
    for role, patch in roles.items():
        label = "红队" if role == "black" else "蓝队"
        if not isinstance(patch, dict) or set(patch) - {"inherit_main", "base_url", "api_key", "model", "max_tokens", "clear_api_key"}:
            raise ValueError(label + "模型配置格式不正确。")
        previous = cfg.setdefault("arena_models", {}).get(role, {})
        own = dict(previous)
        for flag in ("inherit_main", "clear_api_key"):
            if flag in patch and type(patch[flag]) is not bool:
                raise ValueError(label + "模型开关必须为布尔值。")
        own["inherit_main"] = patch.get("inherit_main", own.get("inherit_main", True))
        for field in ("base_url", "model", "api_key"):
            if field in patch:
                if not isinstance(patch[field], str):
                    raise ValueError(label + "模型字段必须为文本。")
                value = patch[field].strip()
                if field != "api_key" or value:
                    own[field] = value
        if patch.get("clear_api_key"):
            if patch.get("api_key", "").strip():
                raise ValueError(label + "不能同时输入和清除密钥。")
            own["api_key"] = ""
        if (previous.get("api_key") and own.get("base_url", "").rstrip("/") != previous.get("base_url", "").rstrip("/")
                and not patch.get("api_key", "").strip() and not patch.get("clear_api_key")):
            raise ValueError(label + "接口地址已改变，请重新输入密钥；免密接口请勾选清除密钥。")
        if "max_tokens" in patch:
            value = patch["max_tokens"]
            if type(value) is not int or not 64 <= value <= 32768:
                raise ValueError(label + " max_tokens 需为 64–32768 的整数。")
            own["max_tokens"] = value
        if not own["inherit_main"]:
            try:
                parsed = urlsplit(own.get("base_url", ""))
                valid = parsed.scheme in ("http", "https") and parsed.hostname and not (parsed.username or parsed.password or parsed.query or parsed.fragment)
                parsed.port
            except ValueError:
                valid = False
            if not valid or not own.get("model", "").strip():
                raise ValueError(label + "独立配置需要有效的 HTTP(S) 接口地址和模型名称。")
        cfg["arena_models"][role] = own
    return cfg


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


def _cloud_stream(messages, temperature, enable_thinking=False, timeout=600, config=None):
    """云流式：真流式逐块 yield (kind, text)，失败原地抛异常。"""
    c = cloud_cfg() if config is None else config
    payload = {
        "model": c["model"], "stream": True, "temperature": temperature,
        "max_tokens": c["max_tokens"], "messages": messages,
        "chat_template_kwargs": {"enable_thinking": bool(enable_thinking)},
    }
    req = urllib.request.Request(
        c["base_url"].rstrip("/") + "/chat/completions", data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json",
                 **({"Authorization": f"Bearer {c['api_key']}"} if c.get("api_key") else {})})
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
