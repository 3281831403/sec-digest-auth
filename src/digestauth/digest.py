"""HTTP Digest authentication (RFC 7616) challenge parsing and checking.

The public surface is deliberately small: a challenge or an authorization
field value can be parsed, an authorization value can be produced from user
credentials, a response can be verified against a nonce store, and the bare
hash primitive is exposed so that callers can compute their own values.
"""

from __future__ import annotations

import hashlib
import re
from typing import Callable, Dict, List, Mapping, Optional

_ALGORITHMS = {
    "MD5": hashlib.md5,
    "SHA-256": hashlib.sha256,
}

_NC_RE = re.compile(r"^[0-9a-fA-F]{8}$")


def _fail(reason: str) -> Dict[str, object]:
    return {"ok": False, "username": None, "reason": reason}


def hash_hex(algorithm: str, text: str) -> str:
    """Return the lower-case hexadecimal digest of ``text``.

    ``algorithm`` is matched case-insensitively and an optional ``-sess``
    suffix is ignored, because the suffix only changes how the A1 value is
    assembled and never the hash function itself.
    """
    name = (algorithm or "MD5").strip().upper()
    if name.endswith("-SESS"):
        name = name[: -len("-SESS")]
    try:
        func = _ALGORITHMS[name]
    except KeyError:
        raise ValueError("unsupported algorithm: %s" % (algorithm,))
    return func(text.encode("utf-8")).hexdigest()


def _is_sess(algorithm: str) -> bool:
    return (algorithm or "").strip().upper().endswith("-SESS")


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        body = value[1:-1]
        out: List[str] = []
        index = 0
        while index < len(body):
            char = body[index]
            if char == "\\" and index + 1 < len(body):
                out.append(body[index + 1])
                index += 2
                continue
            out.append(char)
            index += 1
        return "".join(out)
    return value


def _quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _split_pairs(text: str) -> List[tuple]:
    """Split ``name=value`` pairs on commas that are outside quoted strings."""
    chunks: List[str] = []
    buffer: List[str] = []
    in_quotes = False
    index = 0
    while index < len(text):
        char = text[index]
        if in_quotes and char == "\\" and index + 1 < len(text):
            buffer.append(char)
            buffer.append(text[index + 1])
            index += 2
            continue
        if char == '"':
            in_quotes = not in_quotes
            buffer.append(char)
        elif char == "," and not in_quotes:
            chunks.append("".join(buffer))
            buffer = []
        else:
            buffer.append(char)
        index += 1
    chunks.append("".join(buffer))

    pairs: List[tuple] = []
    for chunk in chunks:
        chunk = chunk.strip()
        if not chunk:
            continue
        name, sep, value = chunk.partition("=")
        if not sep:
            pairs.append((name.strip().lower(), ""))
            continue
        pairs.append((name.strip().lower(), _unquote(value.strip())))
    return pairs


def _scheme_params(value: str, scheme: str) -> Dict[str, str]:
    text = value.strip()
    if text[: len(scheme)].lower() != scheme.lower():
        raise ValueError("expected a %s value" % (scheme,))
    rest = text[len(scheme):].strip()
    if not rest:
        raise ValueError("empty %s value" % (scheme,))
    return dict(_split_pairs(rest))


def parse_challenge(value: str) -> Dict[str, object]:
    """Parse a ``WWW-Authenticate: Digest ...`` field value."""
    params = _scheme_params(value, "Digest")
    raw_qop = params.get("qop")
    return {
        "realm": params.get("realm", ""),
        "nonce": params.get("nonce", ""),
        "qop": raw_qop if raw_qop else [],
        "algorithm": params.get("algorithm") or "SHA-256",
        "opaque": params.get("opaque"),
        "stale": (params.get("stale") or "").lower() == "true",
    }


def parse_authorization(value: str) -> Dict[str, object]:
    """Parse an ``Authorization: Digest ...`` field value."""
    params = _scheme_params(value, "Digest")
    username = params.get("username")
    if username is not None:
        username = username.lower()
    return {
        "username": username,
        "realm": params.get("realm"),
        "nonce": params.get("nonce"),
        "uri": params.get("uri"),
        "qop": params.get("qop"),
        "nc": params.get("nc"),
        "cnonce": params.get("cnonce"),
        "response": params.get("response"),
        "algorithm": params.get("algorithm") or "MD5",
        "opaque": params.get("opaque"),
    }


def _a1(
    algorithm: str,
    username: str,
    realm: str,
    password: str,
    nonce: Optional[str],
    cnonce: Optional[str],
) -> str:
    base = hash_hex(algorithm, password)
    if _is_sess(algorithm):
        return hash_hex(algorithm, base)
    return base


def _ha2(algorithm: str, method: str, uri: str) -> str:
    return hash_hex(algorithm, "%s:%s" % (method, uri.split("?")[0]))


def _response(
    algorithm: str,
    username: str,
    realm: str,
    password: str,
    method: str,
    uri: str,
    nonce: Optional[str],
    nc: Optional[str],
    cnonce: Optional[str],
    qop: Optional[str],
) -> str:
    ha1 = _a1(algorithm, username, realm, password, nonce, cnonce)
    ha2 = _ha2(algorithm, method, uri)
    if qop:
        return hash_hex(
            algorithm,
            "%s:%s:%s:%s:%s:%s" % (ha1, nonce, nc, cnonce, qop, ha2),
        )
    return hash_hex(algorithm, "%s:%s:%s" % (ha1, nonce, ha2))


def build_authorization(
    user: str,
    password: str,
    method: str,
    uri: str,
    challenge: Mapping[str, object],
    nc: Optional[str] = None,
    cnonce: Optional[str] = None,
) -> str:
    """Build the ``Authorization`` field value answering ``challenge``."""
    algorithm = str(challenge.get("algorithm") or "MD5")
    realm = str(challenge.get("realm") or "")
    nonce = str(challenge.get("nonce") or "")
    offered = challenge.get("qop") or []
    qop: Optional[str] = None
    if offered:
        if "auth" not in offered:
            raise ValueError("no supported qop offered: %r" % (offered,))
        qop = "auth"
        if not nc or not _NC_RE.match(nc):
            raise ValueError("nc must be eight hexadecimal digits")
        if not cnonce:
            raise ValueError("cnonce is required when qop is used")
    response = _response(
        algorithm, user, realm, password, method, uri, nonce, nc, cnonce, qop
    )
    fields = [
        'username="%s"' % _quote(user),
        'realm="%s"' % _quote(realm),
        'nonce="%s"' % _quote(nonce),
        'uri="%s"' % _quote(uri),
        "algorithm=%s" % algorithm,
    ]
    if qop:
        fields.append("qop=%s" % qop)
        fields.append("nc=%s" % nc)
        fields.append('cnonce="%s"' % _quote(str(cnonce)))
    fields.append('response="%s"' % response)
    opaque = challenge.get("opaque")
    if opaque is not None:
        fields.append('opaque="%s"' % _quote(str(opaque)))
    return "Digest " + ", ".join(fields)


def verify(
    header: str,
    method: str,
    uri: str,
    get_password: Callable[[str], Optional[str]],
    nonce_store: Mapping[str, Dict[str, object]],
) -> Dict[str, object]:
    """Check an ``Authorization`` field value against a nonce store."""
    try:
        auth = parse_authorization(header)
    except ValueError:
        return _fail("malformed")
    for field in ("username", "realm", "nonce", "uri", "response"):
        if not auth.get(field):
            return _fail("missing-field")

    if str(auth["uri"]) != uri:
        return _fail("uri-mismatch")

    username = str(auth["username"])
    password = get_password(username)
    if password is None:
        return _fail("unknown-user")

    qop = auth.get("qop")
    if qop is not None and qop not in ("auth", "auth-int"):
        return _fail("unsupported-qop")

    entry = nonce_store.get(str(auth["nonce"]))
    if entry is None:
        return _fail("stale-nonce")
    try:
        expires_in = int(entry.get("expires_in", 0))
    except (TypeError, ValueError):
        return _fail("stale-nonce")
    if expires_in < 0:
        return _fail("stale-nonce")

    nc_value = auth.get("nc")
    cnonce = auth.get("cnonce")
    if qop is not None:
        if not nc_value or not _NC_RE.match(str(nc_value)) or not cnonce:
            return _fail("missing-field")
        last = entry.get("nc")
        if last is not None and str(nc_value) <= str(last):
            return _fail("replay")

    expected = _response(
        str(auth["algorithm"]),
        username,
        str(auth["realm"]),
        password,
        method,
        str(auth["uri"]),
        str(auth["nonce"]),
        str(nc_value) if nc_value is not None else None,
        str(cnonce) if cnonce is not None else None,
        str(qop) if qop is not None else None,
    )
    received = str(auth["response"]).lower()
    if expected != received:
        return _fail("bad-response")

    if qop is not None and nc_value is not None:
        entry["nc"] = str(nc_value)
    return {"ok": True, "username": username, "reason": ""}