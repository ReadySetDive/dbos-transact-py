"""A strict, pickle-free JSON `Serializer` for dbos==3.6.0.

Values are restricted to JSON plus a small tagged vocabulary (tuple, set, bytes, datetime,
date, Decimal, UUID).  Exceptions are stored as {type, message} and come back as
`RemoteError` -- the original exception class is NOT reconstructed (that is the point:
nothing in the database can choose a Python type to instantiate).

Rows written with this serializer carry serialization = 'strict_json'.
"""

from __future__ import annotations

import base64
import json
import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Any

from dbos import Serializer

_TAG = "__t__"


class RemoteError(Exception):
    """An exception read back from the database (original type name in .type_name)."""

    def __init__(self, type_name: str, message: str) -> None:
        super().__init__(message)
        self.type_name = type_name

    def __str__(self) -> str:
        return f"{self.type_name}: {self.args[0]}"


def _enc(o: Any) -> Any:
    if o is None or isinstance(o, (bool, int, float, str)):
        return o
    if isinstance(o, list):
        return [_enc(v) for v in o]
    if isinstance(o, tuple):
        return {_TAG: "tuple", "v": [_enc(v) for v in o]}
    if isinstance(o, (set, frozenset)):
        return {_TAG: "set", "v": [_enc(v) for v in o]}
    if isinstance(o, dict):
        if not all(isinstance(k, str) for k in o):
            raise TypeError("StrictJSONSerializer: dict keys must be str")
        if _TAG in o:
            raise TypeError(f"StrictJSONSerializer: reserved key {_TAG!r}")
        return {k: _enc(v) for k, v in o.items()}
    if isinstance(o, datetime):
        return {_TAG: "datetime", "v": o.isoformat()}
    if isinstance(o, date):
        return {_TAG: "date", "v": o.isoformat()}
    if isinstance(o, Decimal):
        return {_TAG: "decimal", "v": str(o)}
    if isinstance(o, uuid.UUID):
        return {_TAG: "uuid", "v": str(o)}
    if isinstance(o, (bytes, bytearray)):
        return {_TAG: "bytes", "v": base64.b64encode(bytes(o)).decode()}
    if isinstance(o, BaseException):
        tn = o.type_name if isinstance(o, RemoteError) else type(o).__name__
        msg = o.args[0] if isinstance(o, RemoteError) else str(o)
        return {_TAG: "error", "type": tn, "message": str(msg)}
    # Deliberately no repr() of the object in the message (it would end up in logs).
    raise TypeError(f"StrictJSONSerializer: unsupported type {type(o).__module__}.{type(o).__qualname__}")


def _dec(o: Any) -> Any:
    if isinstance(o, list):
        return [_dec(v) for v in o]
    if isinstance(o, dict):
        t = o.get(_TAG)
        if t is None:
            return {k: _dec(v) for k, v in o.items()}
        if t == "tuple":
            return tuple(_dec(v) for v in o["v"])
        if t == "set":
            return set(_dec(v) for v in o["v"])
        if t == "datetime":
            return datetime.fromisoformat(o["v"])
        if t == "date":
            return date.fromisoformat(o["v"])
        if t == "decimal":
            return Decimal(o["v"])
        if t == "uuid":
            return uuid.UUID(o["v"])
        if t == "bytes":
            return base64.b64decode(o["v"])
        if t == "error":
            return RemoteError(str(o["type"]), str(o["message"]))
        raise ValueError(f"StrictJSONSerializer: unknown tag {t!r}")
    return o


class StrictJSONSerializer(Serializer):
    def serialize(self, data: Any) -> str:
        return json.dumps(_enc(data), separators=(",", ":"), ensure_ascii=False)

    def deserialize(self, serialized_data: str) -> Any:
        return _dec(json.loads(serialized_data))

    def name(self) -> str:
        return "strict_json"
