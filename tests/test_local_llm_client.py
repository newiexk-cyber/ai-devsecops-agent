# -*- coding: utf-8 -*-
"""
Unit tests cho Local LLM Client (Ollama).
Kiểm tra: parse JSON từ markdown fence, kiểm tra sức khỏe Ollama offline/online, và gọi chat_json.
"""
import json
import pytest
import httpx

from src.core.local_llm_client import (
    OllamaClient,
    check_ollama_health,
    extract_json_payload,
)


def test_extract_json_payload_handles_markdown_fences_and_noise():
    raw = """Dưới đây là kết quả phân tích bài báo:
```json
{
  "kept_iocs": [{"type": "IP", "value": "185.220.101.5"}],
  "dropped_iocs": []
}
```
Hy vọng giúp ích cho bạn."""
    parsed = extract_json_payload(raw)
    assert parsed["kept_iocs"][0]["value"] == "185.220.101.5"
    assert parsed["dropped_iocs"] == []


def test_extract_json_payload_raises_on_unparseable_text():
    with pytest.raises(ValueError, match="Cannot extract valid JSON"):
        extract_json_payload("Không có dữ liệu json nào ở đây.")


def test_check_ollama_health_online_and_model_detection(monkeypatch):
    class FakeResponse:
        status_code = 200

        def json(self):
            return {
                "models": [
                    {"name": "qwen2.5:3b", "size": 1900000000},
                    {"name": "llama3.2:3b", "size": 2000000000},
                ]
            }

    class FakeClient:
        def __init__(self, timeout=3.0):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, url):
            assert url.endswith("/api/tags")
            return FakeResponse()

    monkeypatch.setattr(httpx, "Client", FakeClient)
    status = check_ollama_health(base_url="http://127.0.0.1:11434", model="qwen2.5:3b")
    assert status["online"] is True
    assert status["model_available"] is True
    assert "qwen2.5:3b" in status["available_models"]
    assert status["error"] is None


def test_check_ollama_health_when_offline(monkeypatch):
    class BrokenClient:
        def __init__(self, timeout=3.0):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, url):
            raise httpx.ConnectError("Connection refused")

    monkeypatch.setattr(httpx, "Client", BrokenClient)
    status = check_ollama_health(base_url="http://127.0.0.1:11434", model="qwen2.5:3b")
    assert status["online"] is False
    assert status["model_available"] is False
    assert "Connection refused" in status["error"]


def test_ollama_client_chat_json_returns_parsed_dict(monkeypatch):
    captured = {}

    class FakeResponse:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {
                "message": {
                    "role": "assistant",
                    "content": json.dumps({"summary": "Akira C2 activity", "kept_iocs": []}),
                }
            }

    class FakeClient:
        def __init__(self, timeout=60.0):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, json=None):
            captured["url"] = url
            captured["payload"] = json
            return FakeResponse()

    monkeypatch.setattr(httpx, "Client", FakeClient)
    client = OllamaClient(base_url="http://127.0.0.1:11434", model="qwen2.5:3b")
    result = client.chat_json("system", "user")

    assert captured["url"] == "http://127.0.0.1:11434/api/chat"
    assert captured["payload"]["model"] == "qwen2.5:3b"
    assert captured["payload"]["format"] == "json"
    assert captured["payload"]["stream"] is False
    assert result["summary"] == "Akira C2 activity"
