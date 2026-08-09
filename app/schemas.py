"""Request bodies.

`extra="forbid"` everywhere: an unknown field is a bug or an attack, never
something to silently ignore.
"""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .config import MAX_BODY_BYTES, MAX_SUBJECT_LEN

HANDLE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,31}$")
LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")

Priority = Literal["low", "normal", "high", "urgent"]
Kind = Literal["message", "update", "request", "broadcast", "ack"]


def normalize_label(raw: str) -> str:
    """A session label is a sub-address, so it obeys the same discipline as a
    handle: lowercase, no separators that could confuse `handle/label` parsing."""
    lab = (raw or "").strip().lstrip("@").lower()
    if not LABEL_RE.match(lab):
        raise ValueError("label must be 1-40 chars, lowercase letters/digits/-/_")
    return lab


def normalize_handle(raw: str) -> str:
    h = (raw or "").strip().lstrip("@").lower()
    if not HANDLE_RE.match(h):
        raise ValueError(
            "handle must be 2-32 chars, lowercase letters/digits/-/_, starting with a letter or digit"
        )
    return h


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class RegisterIn(Strict):
    invite_code: str = Field(min_length=8, max_length=128)
    handle: str = Field(min_length=2, max_length=32)
    display_name: str = Field(min_length=1, max_length=120)
    client: str | None = Field(default=None, max_length=60)

    @field_validator("handle")
    @classmethod
    def _handle(cls, v: str) -> str:
        return normalize_handle(v)


class SendIn(Strict):
    to: str | list[str] = Field(description="handle(s) or chat id(s) of the recipients")
    subject: str = Field(min_length=1, max_length=MAX_SUBJECT_LEN)
    body: str = Field(min_length=1, max_length=MAX_BODY_BYTES)
    kind: Kind = "message"
    priority: Priority = "normal"
    in_reply_to: str | None = Field(default=None, max_length=64)
    as_session: str | None = Field(
        default=None, max_length=40,
        description="label of YOUR session to send from, so replies come back to this conversation")
    attachments: list[str] = Field(
        default_factory=list, max_length=10,
        description="blob ids returned by POST /v1/blobs")

    @field_validator("to")
    @classmethod
    def _to(cls, v):
        items = [v] if isinstance(v, str) else v
        if not items:
            raise ValueError("at least one recipient is required")
        if len(items) > 20:
            raise ValueError("at most 20 recipients per message")
        return items


class InlineBlobIn(Strict):
    filename: str = Field(min_length=1, max_length=120)
    content_base64: str = Field(min_length=1)
    content_type: str | None = Field(default=None, max_length=120)


class SessionIn(Strict):
    label: str = Field(min_length=1, max_length=40)
    display_name: str | None = Field(default=None, max_length=120)

    @field_validator("label")
    @classmethod
    def _label(cls, v: str) -> str:
        return normalize_label(v)


class EditIn(Strict):
    body: str = Field(min_length=1, max_length=MAX_BODY_BYTES)


class InviteIn(Strict):
    note: str | None = Field(default=None, max_length=200)
