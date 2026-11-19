"""Process-side hardening for an MIT-only (no dbos-enterprise, no Conductor) deployment of dbos==3.6.0.

Tested against dbos==3.6.0 only.  Everything here works by wrapping public or semi-public
attributes of the MIT-licensed `dbos` package from the *application* side; nothing in the
proprietary `dbos-enterprise` package is touched (it must not even be installed).

Usage (order matters):

    import dbos_hardening
    dbos_hardening.preimport()                 # BEFORE the first `import dbos`
    from dbos import DBOS, DBOSConfig
    config = dbos_hardening.check_config({...})  # refuses Conductor/enterprise/OTLP settings
    DBOS(config=config)
    dbos_hardening.postconfig(allow_pickle_modules=("myapp.models",))
    DBOS.launch()

Each function can also be used on its own.  See HARDENING.md for what each control was
tested against and its residual risk.
"""

from __future__ import annotations

import builtins
import importlib.abc
import importlib.machinery
import importlib.metadata
import io
import logging
import os
import pickle
import re
import sys
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Sequence, Set, Tuple

EXPECTED_DBOS_VERSION = "3.6.0"

# --------------------------------------------------------------------------------------
# 1. Environment hygiene (R5)
# --------------------------------------------------------------------------------------

# Exact names.  DBOS__CLOUD is read ONCE, at `import dbos`, so scrubbing must precede it.
SCRUB_EXACT = {
    "DBOS_DOMAIN",  # default Conductor host
    "DBOS_APP_NAME",  # cloud override of the app name
    "DBOS_SYSTEM_DATABASE_URL",  # cloud/CLI override of the database URL
    "DBOS_DATABASE_URL",
    "SSLKEYLOGFILE",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",  # selects which libpq/libssl the pure-Python psycopg loads
    "LD_AUDIT",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "PYTHONBREAKPOINT",
    "PYTHONUSERBASE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
}
# Prefixes.  PG* covers every libpq variable (PGHOSTADDR, PGOPTIONS, PGSERVICE, PGSSLMODE,
# PGSSLROOTCERT, PGPASSFILE, PGSYSCONFDIR, PGREQUIREAUTH, PGGSSDELEGATION ...).
SCRUB_PREFIXES = (
    "DBOS__",  # DBOS__CLOUD, DBOS__APPVERSION, DBOS__VMID, DBOS__APPID, DBOS__CONDUCTOR_*, DBOS__OTLP_*
    "PG",
    "OPENSSL_",  # OPENSSL_CONF, OPENSSL_MODULES, OPENSSL_ENGINES: config/provider loading
    "SSL_CERT_",  # SSL_CERT_FILE, SSL_CERT_DIR
    "KRB5",
    "LDAP",
    "SASL_",
    "OTEL_",
    "GSS",
)


def is_scrubbed_name(name: str, keep: Iterable[str] = ()) -> bool:
    if name in keep:
        return False
    return name in SCRUB_EXACT or name.startswith(SCRUB_PREFIXES)


def scrub_environment(keep: Iterable[str] = ()) -> Sequence[str]:
    """Remove dangerous variables from this process' environment.  Returns the names removed.

    In-process fallback for the `dbos-launch` wrapper.  Must run before `import dbos`
    (DBOS__CLOUD is latched at import) and before the first database connection
    (libpq reads PG* at connect time).  os.environ deletion calls unsetenv(3), so libpq,
    OpenSSL and child processes see the change too.
    """
    removed = [n for n in list(os.environ) if is_scrubbed_name(n, keep)]
    for n in removed:
        del os.environ[n]
    return removed


# --------------------------------------------------------------------------------------
# 2. Blocking the proprietary package (R5/R6)
# --------------------------------------------------------------------------------------

BLOCKED_TOP_LEVEL = ("dbos_enterprise",)


class _BlockedImportFinder(importlib.abc.MetaPathFinder):
    """Refuses to import the proprietary package even if it is somehow on sys.path."""

    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> None:
        top = fullname.partition(".")[0]
        if top in BLOCKED_TOP_LEVEL:
            # ModuleNotFoundError with .name set makes dbos core raise its own clean
            # DBOSInitializationError ("... requires the dbos-enterprise package").
            raise ModuleNotFoundError(
                f"import of {fullname!r} is blocked by dbos_hardening (MIT-only deployment)",
                name=top,
            )
        return None


def block_enterprise_import() -> None:
    for top in BLOCKED_TOP_LEVEL:
        if top in sys.modules and sys.modules[top] is not None:
            raise RuntimeError(f"{top} is already imported; call preimport() earlier")
    if not any(isinstance(f, _BlockedImportFinder) for f in sys.meta_path):
        sys.meta_path.insert(0, _BlockedImportFinder())


def enterprise_installed() -> bool:
    """True if the proprietary package is present on disk (ignores our own import block)."""
    for finder in sys.meta_path:
        if isinstance(finder, _BlockedImportFinder):
            continue
        find = getattr(finder, "find_spec", None)
        try:
            if find is not None and find("dbos_enterprise", None) is not None:
                return True
        except Exception:
            continue
    try:
        importlib.metadata.distribution("dbos-enterprise")
        return True
    except importlib.metadata.PackageNotFoundError:
        return False


def preimport(*, scrub: bool = True, keep_env: Iterable[str] = ()) -> None:
    """Call before the first `import dbos`."""
    if "dbos" in sys.modules:
        raise RuntimeError("dbos_hardening.preimport() must run before `import dbos`")
    if scrub:
        scrub_environment(keep_env)
    block_enterprise_import()


# Settings that either need the proprietary package / Conductor, or open an outbound channel.
# NOTE: with any of the first four *plus* a key or conductor_url, dbos 3.6.0 performs an HTTPS
# GET (carrying the key) to the Conductor host from the DBOS() constructor, BEFORE it tries to
# import dbos_enterprise -- so the import block alone does not stop that request.
FORBIDDEN_CONFIG_KEYS = (
    "auto_upgrade",
    "sharding",
    "suspend_mode",
    "external_stores",
    "conductor_key",
    "conductor_url",
    "transact_enterprise_key",
    "conductor_executor_metadata",
    "enable_otlp",
    "otlp_traces_endpoints",
    "otlp_logs_endpoints",
)


def check_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """Fail closed on configuration that an MIT-only intranet deployment must not carry."""
    bad = [k for k in FORBIDDEN_CONFIG_KEYS if config.get(k)]
    if bad:
        raise RuntimeError(
            "dbos_hardening: refusing configuration keys not allowed in an MIT-only "
            f"deployment: {', '.join(sorted(bad))}"
        )
    kwargs = config.get("db_engine_kwargs") or {}
    if not kwargs.get("hide_parameters"):
        raise RuntimeError("dbos_hardening: db_engine_kwargs must set hide_parameters=True")
    if kwargs.get("connect_args"):
        # dbos logs the engine kwargs verbatim at INFO (_sys_db.py:800).
        raise RuntimeError(
            "dbos_hardening: do not use connect_args (logged verbatim at INFO); "
            "put connection settings in the URL"
        )
    if config.get("run_migrations", True):
        raise RuntimeError("dbos_hardening: set run_migrations=False (migrate out of band)")
    for key in ("application_version", "executor_id", "max_executor_threads"):
        if not config.get(key):
            raise RuntimeError(f"dbos_hardening: {key} must be set explicitly")
    return config


def assert_mit_only() -> None:
    """Application-start assertion (after `import dbos`)."""
    from dbos._utils import GlobalParams

    if GlobalParams.dbos_version != EXPECTED_DBOS_VERSION:
        raise RuntimeError(
            f"dbos_hardening was validated against dbos {EXPECTED_DBOS_VERSION}, "
            f"found {GlobalParams.dbos_version}; re-validate before deploying"
        )
    if GlobalParams.dbos_cloud:
        raise RuntimeError("DBOS__CLOUD=true was set when dbos was imported; refusing to start")
    if enterprise_installed():
        raise RuntimeError("the proprietary dbos-enterprise package is installed; refusing to start")
    if "dbos_enterprise" in sys.modules and sys.modules["dbos_enterprise"] is not None:
        raise RuntimeError("dbos_enterprise is imported; refusing to start")


# --------------------------------------------------------------------------------------
# 3. Restricted unpickling for the built-in `py_pickle` decoder (R3)
# --------------------------------------------------------------------------------------

_SAFE_BUILTINS: Set[str] = {
    "dict", "list", "tuple", "set", "frozenset", "str", "bytes", "bytearray", "int", "float",
    "complex", "bool", "range", "slice", "object",
} | {
    # every built-in Exception class: constructing one only stores its args.
    # (SystemExit / KeyboardInterrupt / GeneratorExit are deliberately excluded: dbos re-raises
    # a deserialized workflow error, and those would unwind the worker instead of failing a call.)
    name
    for name, obj in vars(builtins).items()
    if isinstance(obj, type) and issubclass(obj, Exception)
}

_SAFE_GLOBALS: Set[Tuple[str, str]] = {
    ("datetime", "datetime"), ("datetime", "date"), ("datetime", "time"),
    ("datetime", "timedelta"), ("datetime", "timezone"),
    ("decimal", "Decimal"), ("uuid", "UUID"), ("fractions", "Fraction"),
    ("collections", "OrderedDict"), ("collections", "deque"),
    # what dbos 3.6.0 itself pickles into step outputs / errors:
    ("dbos._serialization", "PortableWorkflowError"),
    ("dbos._sys_db", "WorkflowStatus"),
}
# Modules of the dbos package from which *exception classes defined there* may be rebuilt.
_DBOS_ERROR_MODULES = ("dbos._error",)


class PickleDenied(pickle.UnpicklingError):
    pass


def install_pickle_guard(
    *,
    allow_modules: Iterable[str] = (),
    allow_classes: Iterable[str] = (),
    report_only: bool = False,
    on_denied: Optional[Callable[[str, str], None]] = None,
) -> None:
    """Make dbos' built-in pickle decoder refuse anything outside an allow-list.

    allow_modules: application modules whose *classes defined in that module* may be rebuilt
                   (functions and re-exported names such as `from os import system` are refused).
    allow_classes: explicit "module.QualName" entries.
    report_only:   log instead of refusing (roll-out aid; NOT a protection).

    Replaces `dbos._serialization.DefaultSerializer.deserialize`, the single place where
    dbos 3.6.0 (MIT core) calls pickle.loads.  Covers the DBOS runtime, DBOSClient and the
    datasource code because they all resolve the method through that class.
    """
    import base64

    from dbos import _serialization

    allow_mod = tuple(allow_modules)
    allow_cls = {tuple(c.rsplit(".", 1)) for c in allow_classes}
    log = logging.getLogger("dbos_hardening")

    def allowed(module: str, name: str) -> bool:
        if module == "builtins":
            return name in _SAFE_BUILTINS
        if (module, name) in _SAFE_GLOBALS or (module, name) in allow_cls:
            return True
        if module in _DBOS_ERROR_MODULES or module in allow_mod:
            mod = sys.modules.get(module)
            obj = mod
            for part in name.split("."):
                obj = getattr(obj, part, None)
            if not isinstance(obj, type) or obj.__module__ != module:
                return False
            if module in _DBOS_ERROR_MODULES:
                return issubclass(obj, Exception)
            return True
        return False

    class RestrictedUnpickler(pickle.Unpickler):
        def find_class(self, module: str, name: str) -> Any:
            if not allowed(module, name):
                if on_denied is not None:
                    on_denied(module, name)
                if not report_only:
                    raise PickleDenied(
                        f"dbos_hardening: refusing to unpickle global {module}.{name}"
                    )
                log.warning("pickle guard (report-only): would refuse %s.%s", module, name)
            return super().find_class(module, name)

        def persistent_load(self, pid: Any) -> Any:
            raise PickleDenied("dbos_hardening: persistent IDs are not allowed")

    def guarded_deserialize(self: Any, serialized_data: str) -> Any:
        return RestrictedUnpickler(io.BytesIO(base64.b64decode(serialized_data))).load()

    guarded_deserialize.__dbos_hardening__ = True  # type: ignore[attr-defined]
    _serialization.DefaultSerializer.deserialize = guarded_deserialize  # type: ignore[method-assign]

    # ---- self-test: fail closed if a dbos upgrade moved the pickle call somewhere else ----
    inst = _serialization.DBOSDefaultSerializer
    if getattr(type(inst).deserialize, "__dbos_hardening__", False) is not True:
        raise RuntimeError("pickle guard is not in effect on DBOSDefaultSerializer")
    assert inst.deserialize(inst.serialize({"a": [1, (2, 3)], "e": ValueError("x")}))["a"] == [1, (2, 3)]
    if not report_only:

        class _Probe:
            def __reduce__(self) -> Any:
                return (os.getpid, ())

        try:
            _serialization.deserialize_value(
                base64.b64encode(pickle.dumps(_Probe())).decode(), "py_pickle", inst
            )
        except PickleDenied:
            pass
        else:
            raise RuntimeError("pickle guard self-test failed: a __reduce__ gadget was executed")


# --------------------------------------------------------------------------------------
# 4. Log hygiene (R4)
# --------------------------------------------------------------------------------------


class DBOSRedactionFilter(logging.Filter):
    """Redacts the dbos 3.6.0 log lines that embed raw application data.

    (1) Matched by *source location* (file basename + function), not by message text:
      dbos/_outcome.py        Pending._wrap   WARNING "Asyncio task cancelled for workflow or
                                              step functools.partial(<fn>, <args...>)"
      dbos/_serialization.py  serialize       ERROR   "Error serializing object: <repr of object>"
                                              (+ exc_info)
    (2) Matched by text, in the message and in the formatted traceback of ANY dbos record:
      PostgreSQL "DETAIL:  Failing row contains (...)" (CHECK / NOT NULL violations print the
      whole row, payload columns included; SQLAlchemy's hide_parameters does not cover it) and,
      as a backstop in case hide_parameters is ever lost, SQLAlchemy "[parameters: ...]".
    """

    TARGETS = {
        ("_outcome.py", "_wrap"): "Asyncio task cancelled for workflow or step [arguments redacted]",
        ("_serialization.py", "serialize"): "Error serializing object: [object redacted]",
    }
    _PATTERNS = (
        (re.compile(r"Failing row contains \(.*"), "Failing row contains [row redacted]"),
        (re.compile(r"\[parameters: .*"), "[parameters redacted]"),
    )
    _fmt = logging.Formatter()

    @classmethod
    def _scrub(cls, text: str) -> str:
        for pat, repl in cls._PATTERNS:
            text = pat.sub(repl, text)
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        key = (record.filename, record.funcName)
        replacement = self.TARGETS.get(key)
        if replacement is not None and os.sep + "dbos" + os.sep in record.pathname:
            if record.exc_info and record.exc_info[0] is not None:
                replacement += f" ({record.exc_info[0].__name__})"
            record.msg = replacement
            record.args = ()
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
            return True
        try:
            msg = record.getMessage()
            scrubbed = self._scrub(msg)
            if scrubbed != msg:
                record.msg, record.args = scrubbed, ()
            if record.exc_info and record.exc_info[0] is not None:
                text = record.exc_text or self._fmt.formatException(record.exc_info)
                scrubbed = self._scrub(text)
                if scrubbed != text:
                    # logging.Formatter reuses a pre-set exc_text instead of re-formatting.
                    # Handlers that format exc_info themselves (JSON/OTLP) are NOT covered.
                    record.exc_text = scrubbed
        except Exception:
            pass
        return True


def install_log_redaction() -> DBOSRedactionFilter:
    """Attach the filter to the `dbos` logger (all dbos records are emitted on it directly)."""
    logger = logging.getLogger("dbos")
    for f in logger.filters:
        if isinstance(f, DBOSRedactionFilter):
            return f
    flt = DBOSRedactionFilter()
    logger.addFilter(flt)
    return flt


# --------------------------------------------------------------------------------------
# 5. One-call wiring
# --------------------------------------------------------------------------------------


def postconfig(
    *,
    allow_pickle_modules: Iterable[str] = (),
    allow_pickle_classes: Iterable[str] = (),
    pickle_report_only: bool = False,
) -> None:
    """Call after `import dbos` (typically right after DBOS(config=...)), before DBOS.launch()."""
    assert_mit_only()
    install_log_redaction()
    install_pickle_guard(
        allow_modules=allow_pickle_modules,
        allow_classes=allow_pickle_classes,
        report_only=pickle_report_only,
    )


def read_database_url(path_env: str = "APP_DBOS_DB_URL_FILE") -> str:
    """Read the system database URL from a root-owned file (systemd credential / mounted secret)
    instead of an environment variable, and refuse URLs that do not pin TLS."""
    path = os.environ[path_env]
    with open(path, "r", encoding="utf-8") as fh:
        url = fh.read().strip()
    require_pinned_url(url)
    return url


REQUIRED_URL_PARAMS: Mapping[str, Optional[str]] = {
    "sslmode": "verify-full",
    "sslrootcert": None,  # any explicit path
    # libpq >= 16: refuse a server that asks for cleartext/MD5 password or no auth at all
    "require_auth": "scram-sha-256",
}


def require_pinned_url(url: str) -> None:
    from urllib.parse import parse_qs, urlsplit

    parts = urlsplit(url)
    q = {k: v[-1] for k, v in parse_qs(parts.query).items()}
    problems = []
    if not parts.hostname or not parts.port or not parts.username or not parts.path.strip("/"):
        problems.append("host, port, user and database must all be explicit")
    for key, want in REQUIRED_URL_PARAMS.items():
        if key not in q:
            problems.append(f"missing {key}")
        elif want is not None and q[key] != want:
            problems.append(f"{key} must be {want}")
    for key in ("password", "sslpassword", "passfile"):
        if key in q:
            # dbos masks only the URL's password field when it logs the URL at INFO;
            # query-string values are printed verbatim (_sys_db.py:792).
            problems.append(f"{key} must not be passed in the query string")
    if problems:
        raise RuntimeError("dbos_hardening: database URL is not pinned: " + "; ".join(problems))
