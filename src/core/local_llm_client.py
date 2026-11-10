# -*- coding: utf-8 -*-
"""
LOCAL LLM CLIENT - OLLAMA INTERFACE (PHÚC)
Kết nối trực tiếp tới Ollama chạy cục bộ (mặc định http://127.0.0.1:11434)
để phục vụ tác tử CTI đọc hiểu ngữ cảnh bài báo mà không phụ thuộc API đám mây.
"""
import json
import os
import re
from typing import Any, Dict, List, Optional

import httpx

DEFAULT_OLLAMA_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")
DEFAULT_OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")


def extract_json_payload(raw_text: str) -> Dict[str, Any]:
    """
    Trích xuất và giải mã JSON từ câu trả lời thô của LLM cục bộ.
    Hỗ trợ bóc tách khối ```json ... ``` hoặc cặp ngoặc nhọn {...} nằm xen trong văn bản.
    """
    if not raw_text or not raw_text.strip():
        raise ValueError("Cannot extract valid JSON from empty LLM output")

    text = raw_text.strip()

    # Thử parse trực tiếp nếu LLM trả JSON thuần
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    # Bóc tách markdown code fence nếu có
    fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text, flags=re.IGNORECASE)
    if fence_match:
        candidate = fence_match.group(1).strip()
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    # Tìm đoạn {...} cân bằng đầu tiên trong chuỗi
    start_idx = text.find("{")
    if start_idx != -1:
        depth = 0
        in_string = False
        escaped = False
        for i in range(start_idx, len(text)):
            ch = text[i]
            if escaped:
                escaped = False
                continue
            if ch == "\\" and in_string:
                escaped = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if not in_string:
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        snippet = text[start_idx : i + 1]
                        try:
                            parsed = json.loads(snippet)
                            if isinstance(parsed, dict):
                                return parsed
                        except json.JSONDecodeError:
                            break

    raise ValueError("Cannot extract valid JSON object from LLM output")


def check_ollama_health(
    base_url: Optional[str] = None,
    model: Optional[str] = None,
    timeout: float = 3.0,
) -> Dict[str, Any]:
    """Kiểm tra trạng thái hoạt động thực tế của Ollama và sự sẵn sàng của model cục bộ."""
    target_url = (base_url or os.getenv("OLLAMA_BASE_URL") or DEFAULT_OLLAMA_URL).rstrip("/")
    target_model = model or os.getenv("OLLAMA_MODEL") or DEFAULT_OLLAMA_MODEL

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(f"{target_url}/api/tags")
            if resp.status_code != 200:
                return {
                    "online": False,
                    "base_url": target_url,
                    "configured_model": target_model,
                    "model_available": False,
                    "available_models": [],
                    "error": f"Ollama returned HTTP {resp.status_code}",
                }
            data = resp.json()
            models: List[str] = [
                m.get("name", "") for m in data.get("models", []) if m.get("name")
            ]
            # Chấp nhận khớp chính xác hoặc prefix (vd: qwen2.5:3b)
            model_available = any(
                m == target_model or m.startswith(f"{target_model}:")
                for m in models
            )
            return {
                "online": True,
                "base_url": target_url,
                "configured_model": target_model,
                "model_available": model_available,
                "available_models": models,
                "error": None,
            }
    except Exception as exc:
        return {
            "online": False,
            "base_url": target_url,
            "configured_model": target_model,
            "model_available": False,
            "available_models": [],
            "error": str(exc),
        }


class OllamaClient:
    """Client giao tiếp trực tiếp với Ollama `/api/chat`."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = 120.0,
    ):
        self.base_url = (base_url or os.getenv("OLLAMA_BASE_URL") or DEFAULT_OLLAMA_URL).rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL") or DEFAULT_OLLAMA_MODEL
        self.timeout = timeout

    def chat(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        format_json: bool = True,
    ) -> str:
        """Gửi prompt tới Ollama `/api/chat` và nhận về nội dung phản hồi."""
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "keep_alive": "15m",
            "options": {
                "temperature": temperature,
                "num_ctx": 2048,
                "num_predict": 512,
            },
        }
        if format_json:
            payload["format"] = "json"

        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(f"{self.base_url}/api/chat", json=payload)
            resp.raise_for_status()
            data = resp.json()
            return data.get("message", {}).get("content", "")

    def chat_json(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
    ) -> Dict[str, Any]:
        """Gọi LLM với chế độ JSON và trả về dictionary đã parse."""
        raw_content = self.chat(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            temperature=temperature,
            format_json=True,
        )
        return extract_json_payload(raw_content)
