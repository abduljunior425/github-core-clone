#!/usr/bin/env python3
"""A GitHub-compatible git forge: git smart HTTP + REST v3 + GraphQL v4 + MCP.

Single process, Python standard library only, no git binary, no outside service.
Implements the github-core-clone-01 conformance surface:

  * git smart HTTP at /{owner}/{repo}.git
    (protocol v2 upload-pack with ls-refs/fetch, v0 receive-pack)
  * REST v3 under /api/v3 (repos, branches, commits, contents, git refs,
    labels, issues, comments, pull requests)
  * GraphQL v4 at /api/graphql (viewer, repository, issue(s), pull request(s),
    node, __type introspection, create/close/merge/addComment mutations,
    operation batching)
  * MCP at /mcp (2026-07-28 server/discover era, legacy initialize fallback,
    tools/list + tools/call for the six github-mcp-server tools)

Lifecycle: bind an ephemeral port, POST {"port": N} to $MAKEFUN_ENV_URL/register,
poll GET $MAKEFUN_ENV_URL/done until {"done": true}, then exit 0. Without
MAKEFUN_ENV_URL the server runs standalone on FORGE_PORT (default 18080).

Determinism: every id is a counter in creation order, every server-made commit
uses a fixed timestamp, every global id is a stable base64 of its key. No wall
clock and no unseeded randomness enter anything stored or returned.

The viewer login ("adaiversen") is the fixed scenario's viewer: wire.ts's
SCENARIO_SEED is frozen (0x6a09e667f3bcc909), so the token owner's login is a
constant of the contest, verified against the kit's own buildScenario().
"""

import base64
import difflib
import hashlib
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.parse
import urllib.request
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "1.0.0"
SERVER_NAME = "forge"
VIEWER_LOGIN = "adaiversen"
VIEWER_ID = 1000
VIEWER_NAME = "ada iversen"
VIEWER_EMAIL = "adaiversen@example.invalid"
FIXED_EPOCH = 1735689600  # 2025-01-01T00:00:00Z; every server-made timestamp
FIXED_ISO = "2025-01-01T00:00:00Z"
DEFAULT_BRANCH = "main"
ZERO_OID = "0" * 40
TOKEN = os.environ.get("MAKEFUN_SHOP_TOKEN", "")  # empty => accept any bearer
IDENTITY = "%s <%s>" % (VIEWER_NAME, VIEWER_EMAIL)

# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------


def sha1_hex(data):
    return hashlib.sha1(data).hexdigest()


def b64encode(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.b64encode(data).decode("ascii")


def b64decode(text):
    cleaned = re.sub(r"[\r\n\t ]+", "", text or "")
    return base64.b64decode(cleaned)


def gid(kind, *parts):
    """Opaque, stable Relay-style global id: base64 of 'Kind:key:key'."""
    raw = (kind + ":" + ":".join(str(p) for p in parts)).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def gid_decode(value):
    """Decode a global id back to (kind, parts) or None."""
    try:
        padded = value + "=" * (-len(value) % 4)
        raw = base64.urlsafe_b64decode(padded).decode("utf-8")
        bits = raw.split(":")
        return bits[0], bits[1:]
    except Exception:
        return None


def json_bytes(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------------------
# pkt-line framing (git wire protocol)
# ---------------------------------------------------------------------------

FLUSH = b"0000"
DELIM = b"0001"
RESPONSE_END = b"0002"


def pktline(payload):
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    total = len(payload) + 4
    if total > 65520:
        raise ValueError("pkt-line too long")
    return ("%04x" % total).encode("ascii") + payload


def pktlines(*items):
    out = bytearray()
    for item in items:
        if item == "flush":
            out += FLUSH
        elif item == "delim":
            out += DELIM
        elif item == "response-end":
            out += RESPONSE_END
        else:
            out += pktline(item)
    return bytes(out)


class PktLineError(ValueError):
    pass


def parse_pktlines(data):
    """Parse a pkt-line stream into [('data', bytes) | ('flush',) | ('delim',) ...].

    Raises PktLineError on malformed input. Trailing bytes that are not a
    complete pkt-line are an error unless they are the start of a packfile
    (the receive-pack body), which the caller handles separately.
    """
    packets = []
    pos = 0
    n = len(data)
    while pos < n:
        if n - pos < 4:
            raise PktLineError("short pkt-line header")
        head = data[pos:pos + 4]
        try:
            size = int(head.decode("ascii"), 16)
        except ValueError:
            raise PktLineError("bad pkt-line length %r" % head)
        if size == 0:
            packets.append(("flush", b""))
            pos += 4
        elif size == 1:
            packets.append(("delim", b""))
            pos += 4
        elif size == 2:
            packets.append(("response-end", b""))
            pos += 4
        elif size < 4 or pos + size > n:
            raise PktLineError("bad pkt-line size %d" % size)
        else:
            packets.append(("data", data[pos + 4:pos + size]))
            pos += size
    return packets


def split_commands_and_pack(data):
    """Split a receive-pack body into (command pkt-lines, pack bytes)."""
    pos = 0
    n = len(data)
    packets = []
    while pos < n:
        if n - pos < 4:
            raise PktLineError("short pkt-line header")
        head = data[pos:pos + 4]
        try:
            size = int(head.decode("ascii"), 16)
        except ValueError:
            raise PktLineError("bad pkt-line length %r" % head)
        if size == 0:
            packets.append(("flush", b""))
            pos += 4
            break
        if size == 1:
            packets.append(("delim", b""))
            pos += 4
            continue
        if size == 2:
            packets.append(("response-end", b""))
            pos += 4
            continue
        if size < 4 or pos + size > n:
            raise PktLineError("bad pkt-line size %d" % size)
        packets.append(("data", data[pos + 4:pos + size]))
        pos += size
    return packets, data[pos:]


# ---------------------------------------------------------------------------
# Git objects: hashing, parsing, building
# ---------------------------------------------------------------------------

OBJ_COMMIT = 1
OBJ_TREE = 2
OBJ_BLOB = 3
OBJ_TAG = 4
OBJ_OFS_DELTA = 6
OBJ_REF_DELTA = 7
TYPE_BY_CODE = {1: "commit", 2: "tree", 3: "blob", 4: "tag"}
CODE_BY_TYPE = {"commit": 1, "tree": 2, "blob": 3, "tag": 4}


def hash_object(obj_type, data):
    header = ("%s %d\x00" % (obj_type, len(data))).encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def parse_tree(data):
    """Parse tree bytes into [(mode_str, name, oid_hex)] in stored order."""
    entries = []
    pos = 0
    n = len(data)
    while pos < n:
        sp = data.index(b" ", pos)
        mode = data[pos:sp].decode("ascii")
        nul = data.index(b"\x00", sp)
        name = data[sp + 1:nul].decode("utf-8", "surrogateescape")
        oid = data[nul + 1:nul + 21].hex()
        entries.append((mode, name, oid))
        pos = nul + 21
    return entries


def build_tree(entries):
    """Build tree bytes. Entries are (mode, name, oid); sorted git order
    (directory names compare as if they ended with '/')."""
    def sort_key(entry):
        mode, name, _oid = entry
        return name + ("/" if mode == "40000" else "")

    out = bytearray()
    for mode, name, oid in sorted(entries, key=sort_key):
        out += ("%s %s\x00" % (mode, name)).encode("utf-8", "surrogateescape")
        out += bytes.fromhex(oid)
    return bytes(out)


def parse_commit(data):
    """Parse commit bytes into {tree, parents, author, committer, message}."""
    text = data.decode("utf-8", "surrogateescape")
    header, _, message = text.partition("\n\n")
    # The stored object ends the message with a newline; the API view
    # (and git's own display) trims it.
    message = message.rstrip("\n")
    info = {"tree": None, "parents": [], "author": "", "committer": "", "message": message}
    for line in header.split("\n"):
        if line.startswith("tree "):
            info["tree"] = line[5:].strip()
        elif line.startswith("parent "):
            info["parents"].append(line[7:].strip())
        elif line.startswith("author "):
            info["author"] = line[7:]
        elif line.startswith("committer "):
            info["committer"] = line[10:]
    return info


def build_commit(tree, parents, message, timestamp=FIXED_EPOCH, who=IDENTITY):
    stamp = "%d +0000" % timestamp
    lines = ["tree %s" % tree]
    for parent in parents:
        lines.append("parent %s" % parent)
    lines.append("author %s %s" % (who, stamp))
    lines.append("committer %s %s" % (who, stamp))
    lines.append("")
    body = "\n".join(lines) + "\n" + message
    if not body.endswith("\n"):
        body += "\n"
    return body.encode("utf-8", "surrogateescape")


def parse_tag(data):
    text = data.decode("utf-8", "surrogateescape")
    header, _, message = text.partition("\n\n")
    info = {"object": None, "type": None, "tag": None, "tagger": "", "message": message}
    for line in header.split("\n"):
        if line.startswith("object "):
            info["object"] = line[7:].strip()
        elif line.startswith("type "):
            info["type"] = line[5:].strip()
        elif line.startswith("tag "):
            info["tag"] = line[4:].strip()
        elif line.startswith("tagger "):
            info["tagger"] = line[7:]
    return info


def build_tag(obj, obj_type, tag, message, timestamp=FIXED_EPOCH, who=IDENTITY):
    stamp = "%d +0000" % timestamp
    body = "object %s\ntype %s\ntag %s\ntagger %s %s\n\n%s" % (
        obj, obj_type, tag, who, stamp, message)
    if not body.endswith("\n"):
        body += "\n"
    return body.encode("utf-8", "surrogateescape")


# ---------------------------------------------------------------------------
# Packfiles: read (with delta resolution) and write (plain entries)
# ---------------------------------------------------------------------------

def _read_varint(data, pos):
    """Pack entry size varint: returns (value, next_pos)."""
    result = 0
    shift = 0
    while True:
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        shift += 7
        if not (byte & 0x80):
            return result, pos


def _read_ofs_delta_offset(data, pos):
    byte = data[pos]
    pos += 1
    offset = byte & 0x7F
    while byte & 0x80:
        byte = data[pos]
        pos += 1
        offset = ((offset + 1) << 7) | (byte & 0x7F)
    return offset, pos


def _inflate_at(data, pos):
    decomp = zlib.decompressobj()
    out = decomp.decompress(data[pos:])
    consumed = len(data[pos:]) - len(decomp.unused_data)
    return out, pos + consumed


def apply_delta(base, delta):
    src_size, pos = _read_varint(delta, 0)
    if src_size != len(base):
        raise ValueError("delta base size mismatch")
    dst_size, pos = _read_varint(delta, pos)
    out = bytearray()
    n = len(delta)
    while pos < n:
        op = delta[pos]
        pos += 1
        if op & 0x80:
            offset = 0
            size = 0
            for i in range(4):
                if op & (1 << i):
                    offset |= delta[pos] << (8 * i)
                    pos += 1
            for i in range(3):
                if op & (0x10 << i):
                    size |= delta[pos] << (8 * i)
                    pos += 1
            if size == 0:
                size = 0x10000
            out += base[offset:offset + size]
        elif op:
            out += delta[pos:pos + op]
            pos += op
        else:
            raise ValueError("delta opcode 0")
    if len(out) != dst_size:
        raise ValueError("delta result size mismatch")
    return bytes(out)


def parse_pack(data, lookup=None):
    """Parse a packfile into {oid: (type, raw_bytes)}.

    Resolves OFS_DELTA and REF_DELTA entries; REF_DELTA bases may come from
    `lookup` (objects the peer already holds, e.g. thin packs) or from the
    pack itself. Raises ValueError on malformed input.
    """
    if len(data) < 12 or data[:4] != b"PACK":
        raise ValueError("not a packfile")
    version = int.from_bytes(data[4:8], "big")
    if version not in (2, 3):
        raise ValueError("unsupported pack version %d" % version)
    count = int.from_bytes(data[8:12], "big")
    trailer = data[-20:]
    if hashlib.sha1(data[:-20]).digest() != trailer:
        raise ValueError("pack checksum mismatch")
    body = data[12:-20]

    raw_entries = []  # (start_offset, type_code_or_delta, payload_or_base, size)
    pos = 0
    for _ in range(count):
        start = pos
        byte = body[pos]
        pos += 1
        type_code = (byte >> 4) & 0x7
        size = byte & 0x0F
        shift = 4
        while byte & 0x80:
            byte = body[pos]
            pos += 1
            size |= (byte & 0x7F) << shift
            shift += 7
        if type_code == OBJ_OFS_DELTA:
            off, pos = _read_ofs_delta_offset(body, pos)
            payload, pos = _inflate_at(body, pos)
            raw_entries.append((start, "ofs", off, payload, size))
        elif type_code == OBJ_REF_DELTA:
            base_oid = body[pos:pos + 20].hex()
            pos += 20
            payload, pos = _inflate_at(body, pos)
            raw_entries.append((start, "ref", base_oid, payload, size))
        else:
            payload, pos = _inflate_at(body, pos)
            raw_entries.append((start, TYPE_BY_CODE[type_code], None, payload, size))

    objects = {}
    by_offset = {}
    # First pass: plain objects.
    for start, kind, base, payload, size in raw_entries:
        if kind in ("commit", "tree", "blob", "tag"):
            if len(payload) != size:
                raise ValueError("object size mismatch")
            oid = hash_object(kind, payload)
            objects[oid] = (kind, payload)
            by_offset[start] = (kind, payload, oid)
    # Delta passes until everything resolves (deltas may chain).
    pending = [e for e in raw_entries if e[1] in ("ofs", "ref")]
    guard = 0
    while pending:
        guard += 1
        if guard > len(raw_entries) + 5:
            raise ValueError("unresolvable delta chain")
        remaining = []
        progressed = False
        for start, kind, base, payload, size in pending:
            base_obj = None
            if kind == "ofs":
                base_off = start - base
                if base_off in by_offset:
                    base_obj = by_offset[base_off]
            else:
                if base in objects:
                    base_obj = objects[base]
                elif lookup is not None:
                    found = lookup(base)
                    if found is not None:
                        base_obj = found
            if base_obj is None:
                remaining.append((start, kind, base, payload, size))
                continue
            base_type, base_data = base_obj[0], base_obj[1]
            resolved = apply_delta(base_data, payload)
            oid = hash_object(base_type, resolved)
            objects[oid] = (base_type, resolved)
            by_offset[start] = (base_type, resolved, oid)
            progressed = True
        if not progressed:
            raise ValueError("delta base not found")
        pending = remaining
    if len(objects) != count:
        raise ValueError("pack object count mismatch")
    return objects


def build_pack(objects):
    """Build a packfile from {oid: (type, raw_bytes)}; plain entries only,
    ordered by oid for determinism."""
    out = bytearray()
    out += b"PACK"
    out += (2).to_bytes(4, "big")
    out += len(objects).to_bytes(4, "big")
    for oid in sorted(objects):
        obj_type, data = objects[oid]
        code = CODE_BY_TYPE[obj_type]
        size = len(data)
        first = (code << 4) | (size & 0x0F)
        size >>= 4
        header = bytearray()
        if size:
            header.append(first | 0x80)
            while size:
                byte = size & 0x7F
                size >>= 7
                if size:
                    header.append(byte | 0x80)
                else:
                    header.append(byte)
        else:
            header.append(first)
        out += bytes(header)
        out += zlib.compress(data, 6)
    out += hashlib.sha1(bytes(out)).digest()
    return bytes(out)


def empty_pack():
    return build_pack({})


# ---------------------------------------------------------------------------
# Reachability over an object store
# ---------------------------------------------------------------------------

def reachable(objects, tips):
    """All oids reachable from `tips` (commits, tags, trees, blobs)."""
    seen = set()
    stack = [t for t in tips if t and t != ZERO_OID]
    while stack:
        oid = stack.pop()
        if oid in seen:
            continue
        entry = objects.get(oid)
        if entry is None:
            continue
        seen.add(oid)
        obj_type, data = entry
        if obj_type == "commit":
            info = parse_commit(data)
            if info["tree"]:
                stack.append(info["tree"])
            stack.extend(info["parents"])
        elif obj_type == "tag":
            info = parse_tag(data)
            if info["object"]:
                stack.append(info["object"])
        elif obj_type == "tree":
            for _mode, _name, child in parse_tree(data):
                stack.append(child)
    return seen


def is_ancestor(objects, maybe_ancestor, tip):
    """True when maybe_ancestor is reachable from tip (or equal to it)."""
    if maybe_ancestor == tip:
        return True
    return maybe_ancestor in reachable(objects, [tip])


def peel_to_commit(objects, oid):
    """Follow tag objects to the commit they point at (or return oid)."""
    seen = set()
    while oid and oid not in seen:
        seen.add(oid)
        entry = objects.get(oid)
        if entry is None:
            return None
        obj_type, data = entry
        if obj_type == "tag":
            oid = parse_tag(data)["object"]
        else:
            return oid
    return None

# ---------------------------------------------------------------------------
# The forge store
# ---------------------------------------------------------------------------


class NotFound(Exception):
    pass


class Conflict(Exception):
    def __init__(self, message, status=422):
        super().__init__(message)
        self.status = status


def _line_counts(old, new):
    """(additions, deletions) between two byte strings, line based."""
    try:
        old_lines = old.decode("utf-8", "replace").splitlines()
        new_lines = new.decode("utf-8", "replace").splitlines()
    except Exception:
        return (1 if new != old else 0), (1 if new != old else 0)
    matcher = difflib.SequenceMatcher(a=old_lines, b=new_lines, autojunk=False)
    additions = deletions = 0
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag in ("insert", "replace"):
            additions += j2 - j1
        if tag in ("delete", "replace"):
            deletions += _i2 - _i1
    return additions, deletions


class Repo:
    def __init__(self, forge, repo_id, name, owner, private, description):
        self.forge = forge
        self.id = repo_id
        self.name = name
        self.owner = owner
        self.private = bool(private)
        self.description = description or ""
        self.default_branch = DEFAULT_BRANCH
        self.objects = {}  # oid -> (type, raw bytes)
        self.refs = {}  # "refs/heads/main" -> oid
        self.labels = {}  # name -> {"name":..., "color":...}
        self.issues = []  # issue dicts, creation order
        self.next_issue = 1
        self.next_comment = 1
        self.pulls = []  # pull dicts, creation order
        self.next_pull = 1
        self.seq = repo_id  # creation order (== id)

    # -- git objects ------------------------------------------------------
    def put_object(self, obj_type, data):
        oid = hash_object(obj_type, data)
        if oid not in self.objects:
            self.objects[oid] = (obj_type, data)
        return oid

    def get_object(self, oid):
        return self.objects.get(oid)

    def ref_tip(self, ref):
        return self.refs.get(ref)

    def branch_tip(self, branch):
        return self.refs.get("refs/heads/" + branch)

    def head_tip(self):
        return self.branch_tip(self.default_branch)

    def default_commit(self):
        tip = self.head_tip()
        if tip is None:
            return None
        return peel_to_commit(self.objects, tip)

    def resolve_ref(self, ref):
        """Resolve a branch name, full ref, or oid to a commit oid (or None)."""
        if not ref:
            return self.default_commit()
        if ref in self.refs:
            return peel_to_commit(self.objects, self.refs[ref])
        full = "refs/heads/" + ref
        if full in self.refs:
            return peel_to_commit(self.objects, self.refs[full])
        if re.fullmatch(r"[0-9a-f]{40}", ref or ""):
            entry = self.objects.get(ref)
            if entry is not None and entry[0] in ("commit", "tag"):
                return peel_to_commit(self.objects, ref)
        return None

    # -- trees ------------------------------------------------------------
    def tree_entries(self, tree_oid):
        entry = self.objects.get(tree_oid)
        if entry is None or entry[0] != "tree":
            return []
        return parse_tree(entry[1])

    def tree_lookup(self, tree_oid, path):
        """(mode, oid) of `path` in the tree, or None."""
        parts = [p for p in path.split("/") if p != ""]
        current = tree_oid
        for index, part in enumerate(parts):
            found = None
            for mode, name, oid in self.tree_entries(current):
                if name == part:
                    found = (mode, oid)
                    break
            if found is None:
                return None
            if index == len(parts) - 1:
                return found
            if found[0] != "40000":
                return None
            current = found[1]
        return None

    def tree_flatten(self, tree_oid, prefix=""):
        """{path: (mode, oid)} for every blob in the tree, recursively."""
        out = {}
        for mode, name, oid in self.tree_entries(tree_oid):
            path = prefix + name
            if mode == "40000":
                out.update(self.tree_flatten(oid, path + "/"))
            else:
                out[path] = (mode, oid)
        return out

    def tree_with_file(self, base_tree_oid, path, blob_oid):
        """New tree oid = base tree with `path` set to blob_oid (or removed)."""
        parts = [p for p in path.split("/") if p != ""]
        return self._tree_set(base_tree_oid, parts, blob_oid)

    def _tree_set(self, tree_oid, parts, blob_oid):
        entries = list(self.tree_entries(tree_oid)) if tree_oid else []
        name = parts[0]
        if len(parts) == 1:
            entries = [e for e in entries if e[1] != name]
            if blob_oid is not None:
                entries.append(("100644", name, blob_oid))
        else:
            child = None
            rest = [e for e in entries if e[1] != name]
            for mode, entry_name, oid in entries:
                if entry_name == name and mode == "40000":
                    child = oid
            new_child = self._tree_set(child, parts[1:], blob_oid)
            if new_child is None:
                entries = rest
            else:
                entries = rest + [("40000", name, new_child)]
        if not entries:
            return None
        return self.put_object("tree", build_tree(entries))

    def commit_tree(self, commit_oid):
        entry = self.objects.get(commit_oid)
        if entry is None or entry[0] != "commit":
            return None
        return parse_commit(entry[1])["tree"]

    def commit_file_content(self, commit_oid, path):
        tree = self.commit_tree(commit_oid)
        if tree is None:
            return None
        found = self.tree_lookup(tree, path)
        if found is None or found[0] == "40000":
            return None
        entry = self.objects.get(found[1])
        if entry is None:
            return None
        return entry[1]

    # -- commits ----------------------------------------------------------
    def make_commit(self, tree_oid, parents, message):
        data = build_commit(tree_oid, parents, message)
        return self.put_object("commit", data)

    def commit_on_branch(self, branch, path, content, message, update_blob=None):
        """Create a commit on `branch` setting `path` to `content` bytes.

        Creates the branch from the default tip when it does not exist yet;
        creates the repository's first commit when there are no refs at all.
        Returns (commit_oid, blob_oid, created_branch_bool, is_new_file).
        """
        ref = "refs/heads/" + branch
        tip = self.refs.get(ref)
        if tip is None:
            parent = self.default_commit()
            parents = [parent] if parent else []
            base_tree = self.commit_tree(parent) if parent else None
            created_branch = True
        else:
            parent = peel_to_commit(self.objects, tip)
            parents = [parent]
            base_tree = self.commit_tree(parent)
            created_branch = False
        is_new = self.tree_lookup(base_tree, path) is None if base_tree else True
        blob_oid = self.put_object("blob", content)
        new_tree = self.tree_with_file(base_tree, path, blob_oid)
        commit_oid = self.make_commit(new_tree, parents, message)
        self.refs[ref] = commit_oid
        return commit_oid, blob_oid, created_branch, is_new

    def delete_on_branch(self, branch, path, message):
        ref = "refs/heads/" + branch
        tip = self.refs.get(ref)
        if tip is None:
            raise NotFound("branch not found")
        parent = peel_to_commit(self.objects, tip)
        base_tree = self.commit_tree(parent)
        if self.tree_lookup(base_tree, path) is None:
            raise NotFound("file not found")
        new_tree = self.tree_with_file(base_tree, path, None)
        commit_oid = self.make_commit(new_tree if new_tree else self.put_object("tree", build_tree([])), [parent], message)
        self.refs[ref] = commit_oid
        return commit_oid

    def list_commits(self, tip):
        """Commit oids reachable from tip, newest first (DFS pre-order)."""
        out = []
        seen = set()
        stack = [tip] if tip else []
        while stack:
            oid = stack.pop()
            if oid in seen:
                continue
            entry = self.objects.get(oid)
            if entry is None or entry[0] != "commit":
                continue
            seen.add(oid)
            out.append(oid)
            info = parse_commit(entry[1])
            stack.extend(reversed(info["parents"]))
        return out

    def merge_base(self, a, b):
        """First common ancestor of commits a and b (or None)."""
        ancestors_a = set()
        stack = [a] if a else []
        while stack:
            oid = stack.pop()
            if oid in ancestors_a:
                continue
            entry = self.objects.get(oid)
            if entry is None or entry[0] != "commit":
                continue
            ancestors_a.add(oid)
            stack.extend(parse_commit(entry[1])["parents"])
        stack = [b] if b else []
        seen = set()
        while stack:
            oid = stack.pop()
            if oid in seen:
                continue
            seen.add(oid)
            if oid in ancestors_a:
                return oid
            entry = self.objects.get(oid)
            if entry is None or entry[0] != "commit":
                continue
            stack.extend(parse_commit(entry[1])["parents"])
        return None

    def diff_trees(self, base_tree, head_tree):
        """[{filename, status, additions, deletions, changes}] base -> head."""
        base = self.tree_flatten(base_tree) if base_tree else {}
        head = self.tree_flatten(head_tree) if head_tree else {}
        files = []
        for path in sorted(set(base) | set(head)):
            in_base = path in base
            in_head = path in head
            if in_base and not in_head:
                old = self.objects.get(base[path][1], (None, b""))[1]
                _a, d = _line_counts(old, b"")
                files.append({"filename": path, "status": "removed",
                              "additions": 0, "deletions": d, "changes": d})
            elif in_head and not in_base:
                new = self.objects.get(head[path][1], (None, b""))[1]
                a, _d = _line_counts(b"", new)
                files.append({"filename": path, "status": "added",
                              "additions": a, "deletions": 0, "changes": a})
            elif base[path][1] != head[path][1]:
                old = self.objects.get(base[path][1], (None, b""))[1]
                new = self.objects.get(head[path][1], (None, b""))[1]
                a, d = _line_counts(old, new)
                files.append({"filename": path, "status": "modified",
                              "additions": a, "deletions": d, "changes": a + d})
        return files

    def three_way_merge(self, base_commit, head_commit, base_tip_commit):
        """Merge head into base_tip with merge-base base_commit.

        Returns (merged_tree_oid, conflict_bool)."""
        base_tree = self.commit_tree(base_commit) if base_commit else None
        head_tree = self.commit_tree(head_commit)
        tip_tree = self.commit_tree(base_tip_commit)
        base = self.tree_flatten(base_tree) if base_tree else {}
        head = self.tree_flatten(head_tree) if head_tree else {}
        tip = self.tree_flatten(tip_tree) if tip_tree else {}
        merged = dict(tip)
        conflict = False
        for path in sorted(set(base) | set(head) | set(tip)):
            b = base.get(path)
            h = head.get(path)
            t = tip.get(path)
            b_oid = b[1] if b else None
            h_oid = h[1] if h else None
            t_oid = t[1] if t else None
            if h_oid == t_oid:
                continue  # agree (or both absent/unchanged)
            if t_oid == b_oid:
                # only head changed
                if h is None:
                    merged.pop(path, None)
                else:
                    merged[path] = h
            elif h_oid == b_oid:
                # only base tip changed: keep tip
                continue
            else:
                conflict = True
        if conflict:
            return None, True
        # rebuild nested trees from the flat map
        tree_oid = self._build_nested_tree(merged)
        return tree_oid, False

    def _build_nested_tree(self, flat):
        """Build a tree oid from {path: (mode, oid)}."""
        root = {}
        for path, (mode, oid) in flat.items():
            parts = path.split("/")
            node = root
            for part in parts[:-1]:
                node = node.setdefault(part, {})
            node[parts[-1]] = (mode, oid)
        return self._build_tree_node(root)

    def _build_tree_node(self, node):
        entries = []
        for name, value in node.items():
            if isinstance(value, dict):
                child = self._build_tree_node(value)
                entries.append(("40000", name, child))
            else:
                mode, oid = value
                entries.append((mode, name, oid))
        return self.put_object("tree", build_tree(entries))

    # -- REST views ---------------------------------------------------------
    def repo_view(self):
        return {
            "id": self.id,
            "node_id": gid("Repository", self.id),
            "name": self.name,
            "full_name": "%s/%s" % (self.owner, self.name),
            "owner": {"login": self.owner, "id": VIEWER_ID, "type": "User"},
            "private": self.private,
            "description": self.description,
            "default_branch": self.default_branch,
            "fork": False,
            "has_issues": True,
            "created_at": FIXED_ISO,
            "updated_at": FIXED_ISO,
            "html_url": "https://example.invalid/%s/%s" % (self.owner, self.name),
            "url": "/api/v3/repos/%s/%s" % (self.owner, self.name),
        }

    def issue_view(self, issue):
        return {
            "id": issue["db_id"],
            "node_id": issue["gid"],
            "number": issue["number"],
            "title": issue["title"],
            "body": issue["body"],
            "state": issue["state"],
            "labels": [{"name": name, "color": self.labels.get(name, {}).get("color", "ededed")}
                       for name in issue["labels"]],
            "user": {"login": self.owner, "id": VIEWER_ID, "type": "User"},
            "created_at": FIXED_ISO,
            "updated_at": FIXED_ISO,
            "html_url": "https://example.invalid/%s/%s/issues/%d" % (self.owner, self.name, issue["number"]),
            "url": "/api/v3/repos/%s/%s/issues/%d" % (self.owner, self.name, issue["number"]),
        }

    def pull_view(self, pull):
        head_sha = self.branch_tip(pull["head"]) or ""
        base_sha = self.branch_tip(pull["base"]) or ""
        return {
            "id": pull["db_id"],
            "node_id": pull["gid"],
            "number": pull["number"],
            "title": pull["title"],
            "body": pull["body"],
            "state": pull["state"],
            "merged": pull["merged"],
            "merged_at": pull["merged_at"],
            "merge_commit_sha": pull["merge_commit_sha"],
            "head": {"ref": pull["head"], "sha": head_sha,
                     "label": "%s:%s" % (self.owner, pull["head"])},
            "base": {"ref": pull["base"], "sha": base_sha,
                     "label": "%s:%s" % (self.owner, pull["base"])},
            "user": {"login": self.owner, "id": VIEWER_ID, "type": "User"},
            "created_at": FIXED_ISO,
            "updated_at": FIXED_ISO,
            "html_url": "https://example.invalid/%s/%s/pull/%d" % (self.owner, self.name, pull["number"]),
            "url": "/api/v3/repos/%s/%s/pulls/%d" % (self.owner, self.name, pull["number"]),
        }

    def pull_files(self, pull):
        head_commit = peel_to_commit(self.objects, self.branch_tip(pull["head"]) or "")
        base_commit = pull["merge_base"]
        base_tree = self.commit_tree(base_commit) if base_commit else None
        head_tree = self.commit_tree(head_commit) if head_commit else None
        return self.diff_trees(base_tree, head_tree)

    def mergeable_state(self, pull):
        """MERGEABLE / CONFLICTING / UNKNOWN for a pull request."""
        head_tip = self.branch_tip(pull["head"])
        base_tip = self.branch_tip(pull["base"])
        if not head_tip or not base_tip:
            return "UNKNOWN"
        head_commit = peel_to_commit(self.objects, head_tip)
        base_commit = peel_to_commit(self.objects, base_tip)
        if head_commit == base_commit:
            return "UNKNOWN"
        merge_base = self.merge_base(base_commit, head_commit)
        _tree, conflict = self.three_way_merge(merge_base, head_commit, base_commit)
        return "CONFLICTING" if conflict else "MERGEABLE"


class _RWLock:
    """Multiple concurrent readers, one exclusive writer.

    Read paths (GETs, git fetch/ls-refs) only read shared state, so they
    may run in parallel — this is what lets 50 concurrent clones overlap
    instead of queueing behind one global lock. Every mutation takes the
    write lock. Not re-entrant; each request takes exactly one mode.
    """

    def __init__(self):
        self._cond = threading.Condition(threading.Lock())
        self._readers = 0
        self._writer = False
        self._writers_waiting = 0

    def read(self):
        return _RWLock._Guard(self, "read")

    def write(self):
        return _RWLock._Guard(self, "write")

    class _Guard:
        def __init__(self, lock, mode):
            self._lock = lock
            self._mode = mode

        def __enter__(self):
            cond = self._lock._cond
            with cond:
                if self._mode == "read":
                    while self._lock._writer or self._lock._writers_waiting:
                        cond.wait()
                    self._lock._readers += 1
                else:
                    self._lock._writers_waiting += 1
                    try:
                        while self._lock._writer or self._lock._readers:
                            cond.wait()
                    finally:
                        self._lock._writers_waiting -= 1
                    self._lock._writer = True
            return self

        def __exit__(self, *exc):
            cond = self._lock._cond
            with cond:
                if self._mode == "read":
                    self._lock._readers -= 1
                else:
                    self._lock._writer = False
                cond.notify_all()
            return False


def _request_lock_mode(method, path):
    """'read' when the request cannot mutate shared state."""
    if method == "GET":
        return "read"
    if ".git/" in path:
        # git-upload-pack (ls-refs/fetch) is read-only; receive-pack mutates.
        return "read" if "git-upload-pack" in path else "write"
    return "write"


class Forge:
    def __init__(self):
        self.rwlock = _RWLock()
        self.repos = {}  # (owner, name) -> Repo
        self.next_repo_id = 1
        self.next_db_id = 1  # shared counter for issue/PR/comment db ids

    def db_id(self):
        value = self.next_db_id
        self.next_db_id += 1
        return value

    def create_repo(self, name, private, description):
        if not name or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", name):
            raise Conflict("Invalid repository name", 422)
        key = (VIEWER_LOGIN, name)
        if key in self.repos:
            raise Conflict("Repository already exists", 422)
        repo = Repo(self, self.next_repo_id, name, VIEWER_LOGIN, private, description)
        self.next_repo_id += 1
        self.repos[key] = repo
        return repo

    def get_repo(self, owner, name):
        if owner != VIEWER_LOGIN:
            return None
        return self.repos.get((owner, name))

    def list_repos(self):
        return sorted(self.repos.values(), key=lambda r: r.seq)

    # -- issues -------------------------------------------------------------
    def create_issue(self, repo, title, body, labels):
        if title is None or title == "":
            raise Conflict("title is required", 422)
        for label in labels:
            if label not in repo.labels:
                raise Conflict("Label '%s' does not exist" % label, 422)
        number = repo.next_issue
        repo.next_issue += 1
        issue = {
            "number": number,
            "db_id": self.db_id(),
            "gid": gid("Issue", repo.id, number),
            "title": title,
            "body": body or "",
            "state": "open",
            "labels": list(labels),
            "comments": [],
            "seq": number,
        }
        repo.issues.append(issue)
        return issue

    def find_issue(self, repo, number):
        for issue in repo.issues:
            if issue["number"] == number:
                return issue
        return None

    def add_comment(self, repo, issue, body):
        comment_id = repo.next_comment
        repo.next_comment += 1
        comment = {
            "id": self.db_id(),
            "comment_seq": comment_id,
            "gid": gid("IssueComment", repo.id, issue["number"], comment_id),
            "body": body or "",
            "user": {"login": VIEWER_LOGIN, "id": VIEWER_ID, "type": "User"},
            "created_at": FIXED_ISO,
            "updated_at": FIXED_ISO,
        }
        issue["comments"].append(comment)
        return comment

    # -- pull requests --------------------------------------------------------
    def create_pull(self, repo, title, body, head, base):
        if repo.branch_tip(head) is None:
            raise Conflict("head branch '%s' does not exist" % head, 422)
        if repo.branch_tip(base) is None:
            raise Conflict("base branch '%s' does not exist" % base, 422)
        for pull in repo.pulls:
            if pull["head"] == head and pull["state"] == "open":
                raise Conflict("A pull request already exists for %s" % head, 422)
        head_commit = peel_to_commit(repo.objects, repo.branch_tip(head))
        base_commit = peel_to_commit(repo.objects, repo.branch_tip(base))
        merge_base = repo.merge_base(base_commit, head_commit)
        number = repo.next_pull
        repo.next_pull += 1
        pull = {
            "number": number,
            "db_id": self.db_id(),
            "gid": gid("PullRequest", repo.id, number),
            "title": title or "",
            "body": body or "",
            "state": "open",
            "head": head,
            "base": base,
            "merged": False,
            "merged_at": None,
            "merge_commit_sha": None,
            "merge_base": merge_base,
        }
        repo.pulls.append(pull)
        return pull

    def find_pull(self, repo, number):
        for pull in repo.pulls:
            if pull["number"] == number:
                return pull
        return None

    def merge_pull(self, repo, pull, method="squash"):
        if pull["merged"]:
            raise Conflict("Pull request already merged", 405)
        if pull["state"] != "open":
            raise Conflict("Pull request is closed", 405)
        head_tip = repo.branch_tip(pull["head"])
        base_tip = repo.branch_tip(pull["base"])
        if not head_tip or not base_tip:
            raise Conflict("branch not found", 422)
        head_commit = peel_to_commit(repo.objects, head_tip)
        base_commit = peel_to_commit(repo.objects, base_tip)
        merge_base = repo.merge_base(base_commit, head_commit)
        merged_tree, conflict = repo.three_way_merge(merge_base, head_commit, base_commit)
        if conflict:
            raise Conflict("Merge conflict", 405)
        message = "Merge pull request #%d from %s\n\n%s" % (
            pull["number"], pull["head"], pull["title"])
        merge_sha = repo.make_commit(merged_tree, [base_commit], message)
        repo.refs["refs/heads/" + pull["base"]] = merge_sha
        pull["merged"] = True
        pull["state"] = "closed"
        pull["merged_at"] = FIXED_ISO
        pull["merge_commit_sha"] = merge_sha
        return merge_sha, message

# ---------------------------------------------------------------------------
# HTTP plumbing
# ---------------------------------------------------------------------------

FORGE = Forge()
REQUEST_COUNTER = [0]
REQUEST_LOCK = threading.Lock()


def next_request_id():
    with REQUEST_LOCK:
        REQUEST_COUNTER[0] += 1
        return "req-%08x" % REQUEST_COUNTER[0]


class ForgeServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 256

    def __init__(self, address):
        super().__init__(address, ForgeHandler)


class ForgeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Forge/1.0"

    # -- quiet ------------------------------------------------------------
    def log_message(self, *args):
        pass

    def send_response(self, code, message=None):
        # BaseHTTPRequestHandler's default adds a Date header computed with
        # strftime on every response; no client here needs it.
        self.log_request(code)
        self.send_response_only(code, message)
        self.send_header("Server", self.version_string())

    def setup(self):
        super().setup()
        try:
            self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass

    # -- request helpers ----------------------------------------------------
    def _read_body(self):
        if getattr(self, "_body_cache", None) is not None:
            return self._body_cache
        length = self.headers.get("Content-Length")
        if length is None:
            self._body_cache = b""
            return b""
        try:
            size = int(length)
        except ValueError:
            self._body_cache = b""
            return b""
        if size <= 0:
            self._body_cache = b""
            return b""
        self._body_cache = self.rfile.read(size)
        return self._body_cache

    def _send(self, status, body=b"", content_type="application/json",
              extra_headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        headers = {
            "Content-Type": content_type,
            "Content-Length": str(len(body)),
            "X-GitHub-Request-Id": next_request_id(),
        }
        if content_type.startswith("application/json"):
            headers["X-OAuth-Scopes"] = "repo, read:org"
        if extra_headers:
            headers.update(extra_headers)
        try:
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            if body and self.command != "HEAD":
                self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, status, obj, extra_headers=None):
        self._send(status, json_bytes(obj), "application/json", extra_headers)

    def _error(self, status, message):
        self._json(status, {"message": message})

    def _base_url(self):
        host = self.headers.get("Host", "127.0.0.1")
        return "http://%s" % host

    def _auth_ok(self):
        """Bearer check. When TOKEN is unset (local dev), any non-empty
        Bearer token is accepted; a missing header is still a 401."""
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return False
        token = header[7:].strip()
        if not token:
            return False
        if TOKEN:
            return token == TOKEN
        return True

    def _require_auth(self):
        if not self._auth_ok():
            self._error(401, "Requires authentication")
            return False
        return True

    def _json_body(self):
        """Parsed JSON body, or (None, error_response_sent)."""
        raw = self._read_body()
        if not raw:
            return {}, None
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except Exception:
            self._error(400, "Invalid JSON body")
            return None, True
        if not isinstance(parsed, dict):
            self._error(400, "JSON body must be an object")
            return None, True
        return parsed, None

    # -- dispatch -------------------------------------------------------------
    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_PATCH(self):
        self._dispatch("PATCH")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def _dispatch(self, method):
        try:
            # Drain the request body exactly once, up front: a handler that
            # answers 404/405 before reading the body would otherwise leave
            # bytes in the keep-alive stream and poison the next request
            # on the same connection (seen as 501 'Unsupported method').
            self._body_cache = None
            if method in ("POST", "PUT", "PATCH", "DELETE"):
                self._read_body()
            mode = _request_lock_mode(method, self.path)
            guard = FORGE.rwlock.read() if mode == "read" else FORGE.rwlock.write()
            with guard:
                self._route(method)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:  # never drop a connection on an error
            try:
                self._error(500, "Internal error: %s" % exc)
            except Exception:
                pass

    def _route(self, method):
        split = urllib.parse.urlsplit(self.path)
        path = split.path
        query = urllib.parse.parse_qs(split.query)
        # normalize: drop a single trailing slash (except root)
        if len(path) > 1 and path.endswith("/"):
            path = path[:-1]
        parts = [urllib.parse.unquote(p) for p in path.split("/") if p != ""]

        if method == "GET" and path == "/healthz":
            self._json(200, {"ok": True})
            return

        # git smart HTTP: /{owner}/{repo}.git/...
        if len(parts) >= 2 and parts[1].endswith(".git"):
            self._route_git(method, parts, query)
            return

        if len(parts) >= 2 and parts[0] == "api":
            if parts[1] == "v3":
                self._route_rest(method, parts[2:], query)
                return
            if parts[1] == "graphql" and len(parts) == 2:
                if method == "POST":
                    self._route_graphql()
                else:
                    self._error(404, "Not Found")
                return
        if parts == ["mcp"]:
            if method == "POST":
                self._route_mcp()
            elif method == "DELETE":
                self._send(405, b"", "application/json")
            else:
                self._error(405, "Method not allowed")
            return

        self._error(404, "Not Found")

    # ------------------------------------------------------------------
    # git smart HTTP
    # ------------------------------------------------------------------
    def _git_repo(self, parts):
        """(owner, repo, rest) from /{owner}/{repo}.git/... or None."""
        if len(parts) < 2 or not parts[1].endswith(".git"):
            return None
        owner = parts[0]
        repo_name = parts[1][:-4]
        return owner, repo_name, parts[2:]

    def _route_git(self, method, parts, query):
        parsed = self._git_repo(parts)
        if parsed is None:
            self._error(404, "Not Found")
            return
        owner, repo_name, rest = parsed
        if not self._require_auth():
            return
        repo = FORGE.get_repo(owner, repo_name)
        if method == "GET" and rest == ["info", "refs"]:
            service = query.get("service", [None])[0]
            if service not in ("git-upload-pack", "git-receive-pack"):
                self._error(400, "unknown service")
                return
            if repo is None:
                self._error(404, "Not Found")
                return
            self._git_advertise(repo, service)
            return
        if repo is None:
            self._error(404, "Not Found")
            return
        if method == "POST" and rest == ["git-upload-pack"]:
            body = self._read_body()
            self._git_upload_pack(repo, body)
            return
        if method == "POST" and rest == ["git-receive-pack"]:
            body = self._read_body()
            self._git_receive_pack(repo, body)
            return
        self._error(404, "Not Found")

    def _git_refs_sorted(self, repo):
        """Refs in advertisement order: HEAD, heads, tags (peeled after each)."""
        refs = []
        head_tip = repo.head_tip()
        head_oid = head_tip if head_tip else ZERO_OID
        refs.append(("HEAD", head_oid, None))
        for name in sorted(repo.refs):
            if name.startswith("refs/heads/"):
                refs.append((name, repo.refs[name], None))
        for name in sorted(repo.refs):
            if name.startswith("refs/tags/"):
                oid = repo.refs[name]
                peeled = peel_to_commit(repo.objects, oid)
                refs.append((name, oid, peeled if peeled != oid else None))
        return refs

    def _git_advertise(self, repo, service):
        want_v2 = service == "git-upload-pack" and (
            self.headers.get("Git-Protocol", "") == "version=2")
        if want_v2:
            body = pktlines(
                "version 2\n",
                "ls-refs=unborn\n",
                "fetch=shallow\n",
                "object-format=sha1\n",
                "flush",
            )
            self._send(200, body,
                       "application/x-git-upload-pack-advertisement")
            return
        # v0 advertisement
        refs = self._git_refs_sorted(repo)
        caps = ["symref=HEAD:refs/heads/main"]
        if service == "git-upload-pack":
            caps += ["side-band-64k", "thin-pack", "ofs-delta", "multi_ack",
                     "shallow", "no-progress"]
        else:
            caps += ["report-status", "side-band-64k", "delete-refs",
                     "ofs-delta"]
        out = bytearray()
        out += pktline("# service=%s\n" % service)
        out += FLUSH
        if not refs:
            first = "%s capabilities^{}\x00%s\n" % (ZERO_OID, " ".join(caps))
            out += pktline(first)
        else:
            for index, (name, oid, peeled) in enumerate(refs):
                if index == 0:
                    line = "%s %s\x00%s\n" % (oid, name, " ".join(caps))
                else:
                    line = "%s %s\n" % (oid, name)
                out += pktline(line)
                if peeled:
                    out += pktline("%s %s^{}\n" % (peeled, name))
        out += FLUSH
        ctype = ("application/x-%s-advertisement" % service)
        self._send(200, bytes(out), ctype)

    def _git_ls_refs(self, repo, args):
        """Answer a v2 ls-refs command. args: list of argument lines."""
        peel = "peel" in args
        symrefs = "symrefs" in args
        unborn = "unborn" in args
        prefixes = [a[11:] for a in args if a.startswith("ref-prefix ")]
        out = bytearray()
        head_tip = repo.head_tip()
        entries = []
        # HEAD is listed when no prefix filter is given, or when a prefix
        # matches the name "HEAD" itself (e.g. git clone sends
        # ref-prefix HEAD). It must NOT leak into unrelated prefixes:
        # the ls-refs-prefix check rejects any ref not starting with the
        # requested prefix.
        head_matches = (not prefixes) or any(
            "HEAD".startswith(p) for p in prefixes)
        if head_matches:
            if head_tip:
                entries.append((head_tip, "HEAD",
                                "refs/heads/main" if symrefs else None, None))
            else:
                if unborn:
                    entries.append((None, "HEAD",
                                    "refs/heads/main" if symrefs else None, None))
        for name in sorted(repo.refs):
            if prefixes and not any(name.startswith(p) for p in prefixes):
                continue
            oid = repo.refs[name]
            peeled = None
            if peel and name.startswith("refs/tags/"):
                target = peel_to_commit(repo.objects, oid)
                if target and target != oid:
                    peeled = target
            entries.append((oid, name, None, peeled))
        for oid, name, symref_target, peeled in entries:
            if oid is None:
                line = "unborn %s" % name
            else:
                line = "%s %s" % (oid, name)
            if symref_target:
                line += " symref-target:%s" % symref_target
            if peeled:
                line += " peeled:%s" % peeled
            out += pktline(line + "\n")
        out += FLUSH
        self._send(200, bytes(out), "application/x-git-upload-pack-result")

    def _git_fetch_v2(self, repo, args):
        wants = []
        haves = []
        shallow_in = []
        depth = None
        done = False
        for arg in args:
            if arg.startswith("want "):
                wants.append(arg[5:].strip())
            elif arg.startswith("have "):
                haves.append(arg[5:].strip())
            elif arg.startswith("shallow "):
                shallow_in.append(arg[8:].strip())
            elif arg.startswith("deepen "):
                try:
                    depth = int(arg[7:].strip())
                except ValueError:
                    depth = None
            elif arg == "done":
                done = True
        objects, shallow_out, unshallow_out = self._fetch_objects(
            repo, wants, haves, shallow_in, depth)
        pack = build_pack(objects)
        chunk_size = 65000
        out = bytearray()
        if not done:
            # Negotiation round (no "done" yet): the acknowledgments
            # section is sent, and the pack only when a cut point is
            # found. Per protocol-v2, acknowledgments MUST be omitted
            # once the client sends "done".
            out += pktline("acknowledgments\n")
            known = set()
            if wants:
                want_reach = reachable(repo.objects, wants)
                known = {h for h in haves if h in want_reach}
            if known:
                for oid in sorted(known):
                    out += pktline("ACK %s\n" % oid)
            else:
                out += pktline("NAK\n")
            if haves and known == set(haves):
                # Cut point found: send "ready" and the pack now.
                out += pktline("ready\n")
                out += DELIM
                if shallow_out or unshallow_out:
                    out += pktline("shallow-info\n")
                    for oid in shallow_out:
                        out += pktline("shallow %s\n" % oid)
                    for oid in unshallow_out:
                        out += pktline("unshallow %s\n" % oid)
                    out += DELIM
                out += pktline("packfile\n")
                for start in range(0, len(pack), chunk_size):
                    out += pktline(b"\x01" + pack[start:start + chunk_size])
                out += FLUSH
                self._send(200, bytes(out), "application/x-git-upload-pack-result")
                return
            out += FLUSH
            self._send(200, bytes(out), "application/x-git-upload-pack-result")
            return
        # Client sent "done": acknowledgments are omitted entirely.
        if shallow_out or unshallow_out:
            out += pktline("shallow-info\n")
            for oid in shallow_out:
                out += pktline("shallow %s\n" % oid)
            for oid in unshallow_out:
                out += pktline("unshallow %s\n" % oid)
            out += DELIM
        out += pktline("packfile\n")
        # sideband: pack bytes in band 1, chunked under the pkt-line limit
        for start in range(0, len(pack), chunk_size):
            chunk = pack[start:start + chunk_size]
            out += pktline(b"\x01" + chunk)
        out += FLUSH
        self._send(200, bytes(out), "application/x-git-upload-pack-result")

    def _fetch_objects(self, repo, wants, haves, shallow_in, depth):
        """Compute the pack contents for a fetch.

        Returns (objects dict, shallow boundaries, unshallow boundaries).

        Depth semantics (git's): a commit at distance d from a want is sent
        when d < depth; the deepest sent generation (d == depth - 1) is the
        new shallow boundary. A client shallow boundary is unshallow when it
        is sent here with its parents also sent.
        """
        objects = repo.objects
        if not wants:
            return {}, [], []
        # Objects the client already holds. A commit on the client's
        # shallow boundary is held itself (with its tree), but its
        # parents are NOT held — that is what makes a shallow client
        # shallow. Treating haves as fully held would make a deepen
        # fetch send nothing.
        held = set()
        if haves:
            shallow_set = set(shallow_in)
            stack = list(haves)
            while stack:
                oid = stack.pop()
                if oid in held:
                    continue
                entry = objects.get(oid)
                if entry is None:
                    continue
                held.add(oid)
                obj_type, data = entry
                if obj_type == "commit":
                    info = parse_commit(data)
                    if info["tree"]:
                        held |= reachable(objects, [info["tree"]])
                    if oid not in shallow_set:
                        stack.extend(info["parents"])
                elif obj_type == "tag":
                    target = parse_tag(data)["object"]
                    if target:
                        stack.append(target)
                elif obj_type == "tree":
                    held |= reachable(objects, [oid])
        # Walk commits from the wants, tracking the smallest distance seen.
        dist = {}
        stack = [(w, 0) for w in wants]
        included = set()
        while stack:
            oid, d = stack.pop()
            if oid in dist and dist[oid] <= d:
                continue
            entry = objects.get(oid)
            if entry is None:
                continue
            obj_type, data = entry
            if obj_type == "tag":
                included.add(oid)
                target = parse_tag(data)["object"]
                if target:
                    target_entry = objects.get(target)
                    if target_entry and target_entry[0] == "commit":
                        stack.append((target, d))
                    else:
                        included |= reachable(objects, [target])
                dist[oid] = d
                continue
            if obj_type != "commit":
                included.add(oid)
                dist[oid] = d
                continue
            if depth is not None and d >= depth:
                dist[oid] = d
                continue  # cut off: not sent, not a boundary itself
            dist[oid] = d
            included.add(oid)
            info = parse_commit(data)
            if info["tree"]:
                included |= reachable(objects, [info["tree"]])
            for parent in info["parents"]:
                stack.append((parent, d + 1))
        send = {oid: objects[oid] for oid in included - held if oid in objects}
        shallow_out = []
        unshallow_out = []
        if depth is not None:
            for oid, d in dist.items():
                entry = objects.get(oid)
                if entry is None or entry[0] != "commit":
                    continue
                if d == depth - 1 and oid in included:
                    shallow_out.append(oid)
            for oid in shallow_in:
                entry = objects.get(oid)
                if entry is None or entry[0] != "commit":
                    continue
                if oid not in included:
                    continue
                parents = parse_commit(entry[1])["parents"]
                if all(p in included for p in parents):
                    unshallow_out.append(oid)
            shallow_out.sort()
            unshallow_out.sort()
        return send, shallow_out, unshallow_out

    def _git_upload_pack(self, repo, body):
        try:
            packets, _rest = split_commands_and_pack(body)
        except PktLineError:
            self._error(400, "invalid pkt-line")
            return
        lines = []
        command = None
        for kind, payload in packets:
            if kind == "flush":
                break
            if kind == "delim":
                lines.append("delim")
                continue
            text = payload.decode("utf-8", "surrogateescape")
            if command is None and text.startswith("command="):
                command = text[len("command="):].strip()
            else:
                lines.append(text.rstrip("\n"))
        if command is None:
            # v0 fetch shape: want/have lines directly
            self._git_fetch_v0(repo, lines)
            return
        args = [line for line in lines if line != "delim"]
        if command == "ls-refs":
            self._git_ls_refs(repo, args)
        elif command == "fetch":
            self._git_fetch_v2(repo, args)
        else:
            self._error(400, "unknown command %s" % command)

    def _git_fetch_v0(self, repo, lines):
        wants, haves, shallow_in, depth = [], [], [], None
        for line in lines:
            if line.startswith("want "):
                wants.append(line[5:].split(" ")[0])
            elif line.startswith("have "):
                haves.append(line[5:].strip())
            elif line.startswith("shallow "):
                shallow_in.append(line[8:].strip())
            elif line.startswith("deepen "):
                try:
                    depth = int(line[7:].strip())
                except ValueError:
                    depth = None
        objects, shallow_out, unshallow_out = self._fetch_objects(
            repo, wants, haves, shallow_in, depth)
        pack = build_pack(objects)
        out = bytearray()
        out += pktline("NAK\n")
        for oid in shallow_out:
            out += pktline("shallow %s\n" % oid)
        for oid in unshallow_out:
            out += pktline("unshallow %s\n" % oid)
        chunk_size = 65000
        for start in range(0, len(pack), chunk_size):
            out += pktline(b"\x01" + pack[start:start + chunk_size])
        out += FLUSH
        self._send(200, bytes(out), "application/x-git-upload-pack-result")

    def _git_receive_pack(self, repo, body):
        try:
            packets, pack_bytes = split_commands_and_pack(body)
        except PktLineError:
            self._send_report(repo, "unpack error: malformed request\n", [])
            return
        commands = []
        for kind, payload in packets:
            if kind != "data":
                continue
            text = payload.decode("utf-8", "surrogateescape").rstrip("\n")
            nul = text.find("\x00")
            if nul >= 0:
                text = text[:nul]
            bits = text.split(" ")
            if len(bits) != 3:
                continue
            commands.append((bits[0], bits[1], bits[2]))
        unpack_error = None
        new_objects = {}
        if pack_bytes:
            try:
                new_objects = parse_pack(
                    pack_bytes,
                    lookup=lambda oid: repo.objects.get(oid))
            except ValueError as exc:
                unpack_error = "unpack error: %s" % exc
        report = []
        if unpack_error is None:
            for oid, (obj_type, data) in new_objects.items():
                repo.objects[oid] = (obj_type, data)
            for old_oid, new_oid, ref in commands:
                current = repo.refs.get(ref)
                if new_oid == ZERO_OID:
                    if current is None:
                        report.append((ref, False, "no such ref"))
                    elif current != old_oid and old_oid != ZERO_OID:
                        report.append((ref, False, "old value does not match"))
                    else:
                        del repo.refs[ref]
                        report.append((ref, True, ""))
                    continue
                if new_oid not in repo.objects:
                    report.append((ref, False, "object not found"))
                    continue
                if old_oid == ZERO_OID:
                    if current is not None:
                        report.append((ref, False, "already exists"))
                    else:
                        repo.refs[ref] = new_oid
                        report.append((ref, True, ""))
                    continue
                if current is None:
                    report.append((ref, False, "no such ref"))
                    continue
                if current != old_oid:
                    report.append((ref, False, "old value does not match"))
                    continue
                if not is_ancestor(repo.objects, old_oid, new_oid):
                    report.append((ref, False, "non-fast-forward"))
                    continue
                repo.refs[ref] = new_oid
                report.append((ref, True, ""))
            self._send_report(repo, "unpack ok\n", report)
        else:
            self._send_report(repo, unpack_error + "\n", [])
            return

    def _send_report(self, repo, unpack_line, report):
        inner = bytearray()
        inner += pktline(unpack_line)
        for ref, ok, reason in report:
            if ok:
                inner += pktline("ok %s\n" % ref)
            else:
                inner += pktline("ng %s %s\n" % (ref, reason))
        inner += FLUSH
        out = bytearray()
        out += pktline(b"\x01" + bytes(inner))
        out += FLUSH
        self._send(200, bytes(out), "application/x-git-receive-pack-result")

    # ------------------------------------------------------------------
    # REST v3 (/api/v3/...)
    # ------------------------------------------------------------------
    def _route_rest(self, method, parts, query):
        if not self._require_auth():
            return
        # GET /api/v3/ and /api/v3/meta
        if parts == []:
            if method == "GET":
                self._json(200, {
                    "current_user_url": "/api/v3/user",
                    "rate_limit_url": "/api/v3/rate_limit",
                    "repository_url": "/api/v3/repos/{owner}/{repo}",
                })
            else:
                self._error(404, "Not Found")
            return
        if parts == ["meta"]:
            if method == "GET":
                self._json(200, {"installed_version": VERSION})
            else:
                self._error(404, "Not Found")
            return
        if parts == ["user"]:
            if method == "GET":
                self._json(200, {
                    "login": VIEWER_LOGIN, "id": VIEWER_ID,
                    "name": VIEWER_NAME, "email": VIEWER_EMAIL,
                    "type": "User",
                })
            else:
                self._error(404, "Not Found")
            return
        if parts[:2] == ["user", "repos"]:
            if len(parts) == 2:
                if method == "POST":
                    self._rest_create_repo()
                elif method == "GET":
                    self._rest_list_repos(query)
                else:
                    self._error(404, "Not Found")
            else:
                self._error(404, "Not Found")
            return
        if parts and parts[0] == "repos" and len(parts) >= 3:
            self._route_rest_repo(method, parts[1], parts[2], parts[3:], query)
            return
        self._error(404, "Not Found")

    def _paginate(self, items, query, base_path):
        """Slice items by page/per_page; returns (page_items, link_header)."""
        try:
            per_page = int(query.get("per_page", ["30"])[0])
        except ValueError:
            per_page = 30
        per_page = max(1, min(per_page, 100))
        try:
            page = int(query.get("page", ["1"])[0])
        except ValueError:
            page = 1
        page = max(1, page)
        total = len(items)
        pages = max(1, (total + per_page - 1) // per_page)
        start = (page - 1) * per_page
        page_items = items[start:start + per_page]
        links = []
        base = self._base_url() + base_path
        if page < pages:
            links.append('<%s?per_page=%d&page=%d>; rel="next"' % (base, per_page, page + 1))
            links.append('<%s?per_page=%d&page=%d>; rel="last"' % (base, per_page, pages))
        if page > 1:
            links.append('<%s?per_page=%d&page=%d>; rel="prev"' % (base, per_page, page - 1))
            links.append('<%s?per_page=%d&page=1>; rel="first"' % (base, per_page))
        return page_items, (", ".join(links) if links else None)

    def _rest_create_repo(self):
        body, err = self._json_body()
        if err:
            return
        name = body.get("name")
        try:
            repo = FORGE.create_repo(name, body.get("private", False),
                                     body.get("description", ""))
        except Conflict as exc:
            self._error(exc.status, str(exc))
            return
        self._json(201, repo.repo_view())

    def _rest_list_repos(self, query):
        repos = FORGE.list_repos()
        page_items, link = self._paginate(
            [r.repo_view() for r in repos], query, "/api/v3/user/repos")
        extra = {"Link": link} if link else None
        self._json(200, page_items, extra)

    def _route_rest_repo(self, method, owner, name, rest, query):
        repo = FORGE.get_repo(owner, name)
        if repo is None:
            self._error(404, "Not Found")
            return
        if rest == []:
            if method == "GET":
                self._json(200, repo.repo_view())
            elif method == "PATCH":
                body, err = self._json_body()
                if err:
                    return
                if "description" in body:
                    repo.description = body["description"] or ""
                if "private" in body:
                    repo.private = bool(body["private"])
                self._json(200, repo.repo_view())
            elif method == "DELETE":
                del FORGE.repos[(owner, name)]
                self._send(204, b"")
            else:
                self._error(404, "Not Found")
            return
        head = rest[0]
        if head == "branches":
            if len(rest) == 1 and method == "GET":
                out = [{"name": ref[11:], "commit": {"sha": oid}}
                       for ref, oid in sorted(repo.refs.items())
                       if ref.startswith("refs/heads/")]
                self._json(200, out)
            elif len(rest) == 2 and method == "GET":
                tip = repo.branch_tip(rest[1])
                if tip is None:
                    self._error(404, "Not Found")
                else:
                    self._json(200, {"name": rest[1],
                                     "commit": {"sha": tip}})
            else:
                self._error(404, "Not Found")
            return
        if head == "commits":
            if method == "GET":
                ref = query.get("sha", [None])[0]
                tip = repo.resolve_ref(ref) if ref else repo.default_commit()
                commits = repo.list_commits(tip) if tip else []
                views = []
                for oid in commits:
                    info = parse_commit(repo.objects[oid][1])
                    views.append({
                        "sha": oid,
                        "commit": {
                            "message": info["message"],
                            "author": {"name": VIEWER_NAME,
                                       "email": VIEWER_EMAIL,
                                       "date": FIXED_ISO},
                            "committer": {"name": VIEWER_NAME,
                                          "email": VIEWER_EMAIL,
                                          "date": FIXED_ISO},
                        },
                        "parents": [{"sha": p} for p in info["parents"]],
                    })
                page_items, link = self._paginate(
                    views, query,
                    "/api/v3/repos/%s/%s/commits" % (owner, name))
                self._json(200, page_items,
                           {"Link": link} if link else None)
            else:
                self._error(404, "Not Found")
            return
        if head == "git" and len(rest) >= 2 and rest[1] == "refs":
            self._route_git_refs(method, repo, rest[2:])
            return
        if head == "contents":
            self._route_contents(method, repo, rest[1:], query)
            return
        if head == "labels":
            if method == "POST" and len(rest) == 1:
                body, err = self._json_body()
                if err:
                    return
                label_name = body.get("name")
                if not label_name:
                    self._error(422, "name is required")
                    return
                color = body.get("color", "ededed")
                repo.labels[label_name] = {"name": label_name, "color": color}
                self._json(201, repo.labels[label_name])
            elif method == "GET" and len(rest) == 1:
                self._json(200, list(repo.labels.values()))
            else:
                self._error(404, "Not Found")
            return
        if head == "issues":
            self._route_issues(method, repo, rest[1:], query)
            return
        if head == "pulls":
            self._route_pulls(method, repo, rest[1:], query)
            return
        self._error(404, "Not Found")

    def _route_git_refs(self, method, repo, rest):
        if method == "POST" and rest == []:
            body, err = self._json_body()
            if err:
                return
            ref = body.get("ref", "")
            sha = body.get("sha", "")
            if not ref.startswith("refs/") or not re.fullmatch(r"[0-9a-f]{40}", sha or ""):
                self._error(422, "Invalid ref or sha")
                return
            if ref in repo.refs:
                self._error(422, "Reference already exists")
                return
            if sha not in repo.objects:
                self._error(422, "Object does not exist")
                return
            repo.refs[ref] = sha
            self._json(201, {"ref": ref, "object": {"sha": sha}})
            return
        if method == "GET":
            if rest == []:
                out = [{"ref": ref, "object": {"sha": oid}}
                       for ref, oid in sorted(repo.refs.items())]
                self._json(200, out)
                return
            ref = "refs/" + "/".join(rest)
            oid = repo.refs.get(ref)
            if oid is None:
                self._error(404, "Not Found")
                return
            self._json(200, {"ref": ref, "object": {"sha": oid}})
            return
        self._error(404, "Not Found")

    def _route_contents(self, method, repo, rest, query):
        if not rest:
            self._error(404, "Not Found")
            return
        path = "/".join(rest)
        if method == "PUT":
            body, err = self._json_body()
            if err:
                return
            content_b64 = body.get("content")
            if content_b64 is None:
                self._error(422, "content is required")
                return
            try:
                content = b64decode(content_b64)
            except Exception:
                self._error(422, "content is not valid base64")
                return
            message = body.get("message") or ("Update %s" % path)
            branch = body.get("branch") or repo.default_branch
            sha = body.get("sha")
            tip = repo.branch_tip(branch)
            if tip is not None:
                commit = peel_to_commit(repo.objects, tip)
                current = repo.commit_file_content(commit, path) if commit else None
                if sha is not None:
                    if current is None:
                        self._error(404, "Not Found")
                        return
                    current_blob = repo.tree_lookup(
                        repo.commit_tree(commit), path)
                    if current_blob is None or current_blob[1] != sha:
                        self._error(409, "sha does not match the current blob")
                        return
                    created = False
                else:
                    created = current is None
            else:
                if sha is not None:
                    self._error(404, "Not Found")
                    return
                created = True
            try:
                commit_oid, blob_oid, _new_branch, _is_new = repo.commit_on_branch(
                    branch, path, content, message)
            except NotFound:
                self._error(404, "Not Found")
                return
            self._json(201 if created else 200, {
                "content": {"name": path.split("/")[-1], "path": path,
                            "sha": blob_oid, "size": len(content),
                            "encoding": "base64"},
                "commit": {"sha": commit_oid},
            })
            return
        if method == "GET":
            ref = query.get("ref", [None])[0]
            commit = repo.resolve_ref(ref) if ref else repo.default_commit()
            if commit is None:
                self._error(404, "Not Found")
                return
            tree = repo.commit_tree(commit)
            found = repo.tree_lookup(tree, path)
            if found is None:
                self._error(404, "Not Found")
                return
            mode, oid = found
            if mode == "40000":
                entries = []
                for sub_mode, sub_name, sub_oid in repo.tree_entries(oid):
                    entry = {"type": "dir" if sub_mode == "40000" else "file",
                             "name": sub_name, "path": path + "/" + sub_name,
                             "sha": sub_oid}
                    if sub_mode != "40000":
                        blob = repo.objects.get(sub_oid)
                        entry["size"] = len(blob[1]) if blob else 0
                    entries.append(entry)
                self._json(200, entries)
                return
            blob = repo.objects.get(oid)
            data = blob[1] if blob else b""
            self._json(200, {
                "type": "file", "encoding": "base64",
                "content": b64encode(data), "sha": oid, "size": len(data),
                "name": path.split("/")[-1], "path": path,
            })
            return
        if method == "DELETE":
            body, err = self._json_body()
            if err:
                return
            message = body.get("message") or ("Delete %s" % path)
            branch = body.get("branch") or repo.default_branch
            sha = body.get("sha")
            tip = repo.branch_tip(branch)
            if tip is None:
                self._error(404, "Not Found")
                return
            commit = peel_to_commit(repo.objects, tip)
            current = repo.tree_lookup(repo.commit_tree(commit), path)
            if current is None:
                self._error(404, "Not Found")
                return
            if sha is not None and current[1] != sha:
                self._error(409, "sha does not match the current blob")
                return
            try:
                commit_oid = repo.delete_on_branch(branch, path, message)
            except NotFound:
                self._error(404, "Not Found")
                return
            self._json(200, {"commit": {"sha": commit_oid}})
            return
        self._error(404, "Not Found")

    def _route_issues(self, method, repo, rest, query):
        if rest == []:
            if method == "POST":
                body, err = self._json_body()
                if err:
                    return
                try:
                    issue = FORGE.create_issue(
                        repo, body.get("title"), body.get("body", ""),
                        body.get("labels", []))
                except Conflict as exc:
                    self._error(exc.status, str(exc))
                    return
                self._json(201, repo.issue_view(issue))
                return
            if method == "GET":
                state = query.get("state", ["open"])[0]
                sort = query.get("sort", ["created"])[0]
                direction = query.get("direction", ["desc"])[0]
                issues = list(repo.issues)
                if state != "all":
                    issues = [i for i in issues if i["state"] == state]
                reverse = direction == "desc"
                if sort == "created":
                    issues.sort(key=lambda i: i["seq"], reverse=reverse)
                views = [repo.issue_view(i) for i in issues]
                page_items, link = self._paginate(
                    views, query,
                    "/api/v3/repos/%s/%s/issues" % (repo.owner, repo.name))
                self._json(200, page_items, {"Link": link} if link else None)
                return
            self._error(404, "Not Found")
            return
        try:
            number = int(rest[0])
        except ValueError:
            self._error(404, "Not Found")
            return
        issue = FORGE.find_issue(repo, number)
        if issue is None:
            self._error(404, "Not Found")
            return
        if len(rest) == 1:
            if method == "GET":
                self._json(200, repo.issue_view(issue))
            elif method == "PATCH":
                body, err = self._json_body()
                if err:
                    return
                if "state" in body and body["state"] in ("open", "closed"):
                    issue["state"] = body["state"]
                if "title" in body:
                    issue["title"] = body["title"]
                if "body" in body:
                    issue["body"] = body["body"]
                self._json(200, repo.issue_view(issue))
            else:
                self._error(404, "Not Found")
            return
        if rest[1] == "comments":
            if method == "POST":
                body, err = self._json_body()
                if err:
                    return
                comment = FORGE.add_comment(repo, issue, body.get("body", ""))
                self._json(201, {
                    "id": comment["id"], "node_id": comment["gid"],
                    "body": comment["body"], "user": comment["user"],
                    "created_at": comment["created_at"],
                    "updated_at": comment["updated_at"],
                })
            elif method == "GET":
                out = [{
                    "id": c["id"], "node_id": c["gid"], "body": c["body"],
                    "user": c["user"], "created_at": c["created_at"],
                    "updated_at": c["updated_at"],
                } for c in issue["comments"]]
                self._json(200, out)
            else:
                self._error(404, "Not Found")
            return
        self._error(404, "Not Found")

    def _route_pulls(self, method, repo, rest, query):
        if rest == []:
            if method == "POST":
                body, err = self._json_body()
                if err:
                    return
                try:
                    pull = FORGE.create_pull(
                        repo, body.get("title"), body.get("body", ""),
                        body.get("head"), body.get("base"))
                except Conflict as exc:
                    self._error(exc.status, str(exc))
                    return
                self._json(201, repo.pull_view(pull))
                return
            if method == "GET":
                state = query.get("state", ["open"])[0]
                pulls = list(repo.pulls)
                if state != "all":
                    pulls = [p for p in pulls if p["state"] == state]
                views = [repo.pull_view(p) for p in pulls]
                page_items, link = self._paginate(
                    views, query,
                    "/api/v3/repos/%s/%s/pulls" % (repo.owner, repo.name))
                self._json(200, page_items, {"Link": link} if link else None)
                return
            self._error(404, "Not Found")
            return
        try:
            number = int(rest[0])
        except ValueError:
            self._error(404, "Not Found")
            return
        pull = FORGE.find_pull(repo, number)
        if pull is None:
            self._error(404, "Not Found")
            return
        if len(rest) == 1:
            if method == "GET":
                self._json(200, repo.pull_view(pull))
            else:
                self._error(404, "Not Found")
            return
        if rest[1] == "files" and len(rest) == 2 and method == "GET":
            self._json(200, repo.pull_files(pull))
            return
        if rest[1] == "merge" and len(rest) == 2 and method == "PUT":
            body, err = self._json_body()
            if err:
                return
            method_name = (body.get("merge_method") or "squash").lower()
            try:
                merge_sha, message = FORGE.merge_pull(repo, pull, method_name)
            except Conflict as exc:
                self._error(exc.status, str(exc))
                return
            self._json(200, {"sha": merge_sha, "merged": True,
                             "message": message})
            return
        self._error(404, "Not Found")

    # ------------------------------------------------------------------
    # GraphQL v4 (/api/graphql)
    # ------------------------------------------------------------------
    def _route_graphql(self):
        if not self._require_auth():
            return
        raw = self._read_body()
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except Exception:
            self._json(400, {"errors": [{"message": "Request body is not valid JSON"}]})
            return
        if isinstance(parsed, list):
            results = [self._graphql_execute(op) for op in parsed]
            self._json(200, results)
        elif isinstance(parsed, dict):
            self._json(200, self._graphql_execute(parsed))
        else:
            self._json(400, {"errors": [{"message": "Request body must be an object"}]})

    # -- document parsing ---------------------------------------------------
    def _graphql_execute(self, operation):
        query = operation.get("query", "")
        variables = operation.get("variables") or {}
        try:
            doc = _gql_parse(query)
        except ValueError as exc:
            return {"data": None, "errors": [{"message": str(exc)}]}
        if not doc:
            return {"data": None, "errors": [{"message": "Empty document"}]}
        op = doc[0]
        try:
            data = _gql_execute(FORGE, op, variables)
        except _GqlFieldError as exc:
            return {"data": {op["selection"][0]["alias"]: None} if op["selection"] else None,
                    "errors": [{"message": str(exc)}]}
        return {"data": data}

    # ------------------------------------------------------------------
    # MCP (/mcp) — JSON-RPC 2.0 over Streamable HTTP, modern 2026-07-28 era
    # ------------------------------------------------------------------
    MCP_TOOLS = [
        {
            "name": "create_repo",
            "description": "Create a repository owned by the viewer.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string",
                             "description": "The repository name."},
                    "description": {"type": "string",
                                    "description": "A short description."},
                    "private": {"type": "boolean",
                                "description": "Whether the repository is private."},
                },
                "required": ["name"],
            },
        },
        {
            "name": "get_repo",
            "description": "Read one repository by owner and name.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "owner": {"type": "string",
                              "description": "The repository owner login."},
                    "repo": {"type": "string",
                             "description": "The repository name."},
                },
                "required": ["owner", "repo"],
            },
        },
        {
            "name": "create_issue",
            "description": "Create an issue in a repository.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "owner": {"type": "string",
                              "description": "The repository owner login."},
                    "repo": {"type": "string",
                             "description": "The repository name."},
                    "title": {"type": "string",
                              "description": "The issue title."},
                    "body": {"type": "string",
                             "description": "The issue body."},
                },
                "required": ["owner", "repo", "title"],
            },
        },
        {
            "name": "list_issues",
            "description": "List a repository's issues.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "owner": {"type": "string",
                              "description": "The repository owner login."},
                    "repo": {"type": "string",
                             "description": "The repository name."},
                    "state": {"type": "string",
                              "description": "open, closed or all."},
                },
                "required": ["owner", "repo"],
            },
        },
        {
            "name": "create_pull_request",
            "description": "Open a pull request from a head branch into a base branch.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "owner": {"type": "string",
                              "description": "The repository owner login."},
                    "repo": {"type": "string",
                             "description": "The repository name."},
                    "title": {"type": "string",
                              "description": "The pull request title."},
                    "body": {"type": "string",
                             "description": "The pull request body."},
                    "head": {"type": "string",
                             "description": "The head branch name."},
                    "base": {"type": "string",
                             "description": "The base branch name."},
                },
                "required": ["owner", "repo", "title", "head", "base"],
            },
        },
        {
            "name": "merge_pull_request",
            "description": "Merge a pull request with a squash commit.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "owner": {"type": "string",
                              "description": "The repository owner login."},
                    "repo": {"type": "string",
                             "description": "The repository name."},
                    "pull_number": {"type": "integer",
                                    "description": "The pull request number."},
                },
                "required": ["owner", "repo", "pull_number"],
            },
        },
    ]

    def _route_mcp(self):
        if not self._require_auth():
            return
        raw = self._read_body()
        try:
            request = json.loads(raw.decode("utf-8"))
        except Exception:
            self._json(400, {"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32700,
                                       "message": "Parse error"}})
            return
        if not isinstance(request, dict):
            self._json(200, {"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32600,
                                       "message": "Invalid Request"}})
            return
        method = request.get("method", "")
        params = request.get("params") or {}
        request_id = request.get("id")
        if request_id is None:
            # A notification (e.g. notifications/initialized): 202, no body.
            self._send(202, b"")
            return
        result, error = self._mcp_dispatch(method, params)
        if error is not None:
            self._json(200, {"jsonrpc": "2.0", "id": request_id,
                             "error": error})
        else:
            self._json(200, {"jsonrpc": "2.0", "id": request_id,
                             "result": result})

    def _mcp_dispatch(self, method, params):
        if method == "server/discover":
            info = {"name": SERVER_NAME, "version": VERSION}
            return {
                "supportedVersions": ["2026-07-28"],
                "serverInfo": info,
                "capabilities": {"tools": {}},
                "_meta": {"io.modelcontextprotocol/serverInfo": info},
            }, None
        if method == "initialize":
            requested = params.get("protocolVersion") or "2025-11-25"
            return {
                "protocolVersion": requested,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": VERSION},
            }, None
        if method == "ping":
            return {}, None
        if method == "tools/list":
            return {"tools": self.MCP_TOOLS}, None
        if method == "tools/call":
            return self._mcp_call(params)
        return None, {"code": -32601, "message": "Method not found: %s" % method}

    def _mcp_tool_result(self, payload, is_error=False):
        text = json.dumps(payload, separators=(",", ":"))
        return {"content": [{"type": "text", "text": text}],
                "structuredContent": payload,
                "isError": bool(is_error)}

    def _mcp_call(self, params):
        name = params.get("name")
        args = params.get("arguments") or {}
        tool = next((t for t in self.MCP_TOOLS if t["name"] == name), None)
        if tool is None:
            return None, {"code": -32602,
                          "message": "Unknown tool: %s" % name}
        required = tool["inputSchema"].get("required", [])
        missing = [key for key in required
                   if key not in args or args[key] is None]
        if missing:
            return None, {"code": -32602,
                          "message": "Missing required arguments: %s"
                                     % ", ".join(missing)}
        try:
            if name == "create_repo":
                repo = FORGE.create_repo(
                    args.get("name"), args.get("private", False),
                    args.get("description", ""))
                return self._mcp_tool_result(repo.repo_view()), None
            if name == "get_repo":
                repo = FORGE.get_repo(args.get("owner"), args.get("repo"))
                if repo is None:
                    return self._mcp_tool_result(
                        {"error": "Repository not found"}, True), None
                return self._mcp_tool_result(repo.repo_view()), None
            if name == "create_issue":
                repo = FORGE.get_repo(args.get("owner"), args.get("repo"))
                if repo is None:
                    return self._mcp_tool_result(
                        {"error": "Repository not found"}, True), None
                issue = FORGE.create_issue(
                    repo, args.get("title"), args.get("body", ""), [])
                return self._mcp_tool_result(repo.issue_view(issue)), None
            if name == "list_issues":
                repo = FORGE.get_repo(args.get("owner"), args.get("repo"))
                if repo is None:
                    return self._mcp_tool_result(
                        {"error": "Repository not found"}, True), None
                state = args.get("state") or "open"
                issues = [i for i in repo.issues
                          if state == "all" or i["state"] == state]
                payload = {"issues": [repo.issue_view(i) for i in issues]}
                return self._mcp_tool_result(payload), None
            if name == "create_pull_request":
                repo = FORGE.get_repo(args.get("owner"), args.get("repo"))
                if repo is None:
                    return self._mcp_tool_result(
                        {"error": "Repository not found"}, True), None
                pull = FORGE.create_pull(
                    repo, args.get("title"), args.get("body", ""),
                    args.get("head"), args.get("base"))
                return self._mcp_tool_result(repo.pull_view(pull)), None
            if name == "merge_pull_request":
                repo = FORGE.get_repo(args.get("owner"), args.get("repo"))
                if repo is None:
                    return self._mcp_tool_result(
                        {"error": "Repository not found"}, True), None
                number = args.get("pull_number")
                try:
                    number = int(number)
                except (TypeError, ValueError):
                    return self._mcp_tool_result(
                        {"error": "pull_number must be an integer"}, True), None
                pull = FORGE.find_pull(repo, number)
                if pull is None:
                    return self._mcp_tool_result(
                        {"error": "Pull request not found"}, True), None
                merge_sha, _message = FORGE.merge_pull(repo, pull, "squash")
                view = repo.pull_view(pull)
                view["sha"] = merge_sha
                return self._mcp_tool_result(view), None
        except Conflict as exc:
            return self._mcp_tool_result({"error": str(exc)}, True), None
        return None, {"code": -32602, "message": "Unknown tool: %s" % name}


class _GqlFieldError(Exception):
    pass


_GQL_TOKEN_RE = re.compile(r"""
    (?P<ws>\s+)
  | (?P<ellipsis>\.\.\.)
  | (?P<name>[_A-Za-z][_A-Za-z0-9]*)
  | (?P<float>-?[0-9]+\.[0-9]+(?:[eE][+-]?[0-9]+)?)
  | (?P<int>-?[0-9]+)
  | (?P<string>"(?:\\.|[^"\\])*")
  | (?P<punct>[!$():=@\[\]{}.|,])
""", re.VERBOSE)


def _gql_tokenize(text):
    tokens = []
    pos = 0
    while pos < len(text):
        match = _GQL_TOKEN_RE.match(text, pos)
        if not match:
            raise ValueError("Unexpected character %r in GraphQL document" % text[pos])
        pos = match.end()
        kind = match.lastgroup
        if kind == "ws":
            continue
        value = match.group()
        if kind == "string":
            value = json.loads(value)
        tokens.append((kind, value))
    tokens.append(("eof", None))
    return tokens


class _GqlParser:
    def __init__(self, text):
        self.tokens = _gql_tokenize(text)
        self.pos = 0

    def peek(self):
        return self.tokens[self.pos]

    def next(self):
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def expect(self, value):
        kind, got = self.next()
        if got != value:
            raise ValueError("Expected %r, got %r" % (value, got))

    def expect_name(self):
        kind, value = self.next()
        if kind != "name":
            raise ValueError("Expected a name, got %r" % (value,))
        return value

    def parse_document(self):
        operations = []
        while self.peek()[0] != "eof":
            operations.append(self.parse_operation())
        return operations

    def parse_operation(self):
        kind, value = self.peek()
        op_type = "query"
        name = None
        if kind == "name" and value in ("query", "mutation", "subscription"):
            self.next()
            op_type = value
            if self.peek()[0] == "name":
                name = self.next()[1]
        elif kind == "punct" and value == "{":
            pass
        else:
            raise ValueError("Expected an operation, got %r" % (value,))
        variables = {}
        if self.peek() == ("punct", "("):
            variables = self.parse_var_defs()
        selection = self.parse_selection_set()
        return {"type": op_type, "name": name, "variables": variables,
                "selection": selection}

    def parse_var_defs(self):
        self.expect("(")
        variables = {}
        while self.peek() != ("punct", ")"):
            self.expect("$")
            name = self.expect_name()
            self.expect(":")
            variables[name] = self.parse_type()
            if self.peek() == ("punct", "="):
                self.next()
                self.parse_value()
            if self.peek() == ("punct", ","):
                self.next()
        self.expect(")")
        return variables

    def parse_type(self):
        kind, value = self.next()
        if kind == "punct" and value == "[":
            inner = self.parse_type()
            self.expect("]")
            result = "[%s]" % inner
        elif kind == "name":
            result = value
        else:
            raise ValueError("Expected a type, got %r" % (value,))
        if self.peek() == ("punct", "!"):
            self.next()
            result += "!"
        return result

    def parse_selection_set(self):
        self.expect("{")
        fields = []
        while self.peek() != ("punct", "}"):
            fields.append(self.parse_selection())
        self.expect("}")
        return fields

    def parse_selection(self):
        if self.peek() == ("ellipsis", "..."):
            self.next()
            kind, value = self.peek()
            if kind == "name" and value == "on":
                self.next()
                type_name = self.expect_name()
                selection = self.parse_selection_set()
                return {"fragment": True, "type": type_name,
                        "selection": selection}
            raise ValueError("Named fragments are not supported")
        name_or_alias = self.expect_name()
        alias = None
        name = name_or_alias
        if self.peek() == ("punct", ":"):
            self.next()
            alias = name_or_alias
            name = self.expect_name()
        args = {}
        if self.peek() == ("punct", "("):
            args = self.parse_args()
        selection = None
        if self.peek() == ("punct", "{"):
            selection = self.parse_selection_set()
        return {"alias": alias or name, "name": name, "args": args,
                "selection": selection}

    def parse_args(self):
        self.expect("(")
        args = {}
        while self.peek() != ("punct", ")"):
            name = self.expect_name()
            self.expect(":")
            args[name] = self.parse_value()
            if self.peek() == ("punct", ","):
                self.next()
        self.expect(")")
        return args

    def parse_value(self):
        kind, value = self.next()
        if kind == "punct" and value == "$":
            return ("var", self.expect_name())
        if kind == "punct" and value == "[":
            items = []
            while self.peek() != ("punct", "]"):
                items.append(self.parse_value())
                if self.peek() == ("punct", ","):
                    self.next()
            self.expect("]")
            return ("list", items)
        if kind == "punct" and value == "{":
            obj = {}
            while self.peek() != ("punct", "}"):
                key = self.expect_name()
                self.expect(":")
                obj[key] = self.parse_value()
                if self.peek() == ("punct", ","):
                    self.next()
            self.expect("}")
            return ("object", obj)
        if kind == "string":
            return ("string", value)
        if kind == "int":
            return ("int", int(value))
        if kind == "float":
            return ("float", float(value))
        if kind == "name":
            if value == "true":
                return ("bool", True)
            if value == "false":
                return ("bool", False)
            if value == "null":
                return ("null", None)
            return ("enum", value)
        raise ValueError("Unexpected value %r" % (value,))


def _gql_parse(text):
    return _GqlParser(text).parse_document()


def _gql_resolve_value(node, variables):
    kind, value = node
    if kind == "var":
        return variables.get(value)
    if kind == "list":
        return [_gql_resolve_value(item, variables) for item in value]
    if kind == "object":
        return {k: _gql_resolve_value(v, variables) for k, v in value.items()}
    return value


# -- schema: type -> {field: resolver-name} for validation -------------------
_GQL_SCHEMA = {
    "Query": {"viewer", "repository", "node", "__type"},
    "User": {"login"},
    "Repository": {"id", "databaseId", "name", "nameWithOwner", "owner",
                   "defaultBranchRef", "viewerPermission", "hasIssuesEnabled",
                   "issue", "issues", "pullRequests", "pullRequest"},
    "Ref": {"name"},
    "Issue": {"id", "number", "title", "state", "body"},
    "IssueConnection": {"nodes", "pageInfo"},
    "PageInfo": {"hasNextPage", "endCursor"},
    "PullRequest": {"id", "number", "state", "merged", "headRefName",
                    "baseRefName", "mergeable", "files"},
    "PullRequestConnection": {"nodes"},
    "PullRequestChangedFileConnection": {"nodes"},
    "PullRequestChangedFile": {"path"},
    "Mutation": {"createIssue", "closeIssue", "createPullRequest",
                 "mergePullRequest", "addComment"},
    "CreateIssuePayload": {"issue"},
    "CloseIssuePayload": {"issue"},
    "CreatePullRequestPayload": {"pullRequest"},
    "MergePullRequestPayload": {"pullRequest"},
    "AddCommentPayload": {"commentEdge"},
    "IssueCommentEdge": {"node"},
    "IssueComment": {"id", "body"},
    "__Type": {"name", "fields", "enumValues"},
    "__Field": {"name"},
    "__EnumValue": {"name"},
    "Node": {"id"},
}

_GQL_TYPE_FIELDS = {
    "Issue": ["id", "number", "title", "state", "body", "url", "createdAt",
              "updatedAt", "author", "labels", "comments"],
    "PullRequest": ["id", "number", "title", "body", "state", "merged",
                    "mergedAt", "headRefName", "baseRefName", "headRefOid",
                    "baseRefOid", "mergeable", "files", "url", "createdAt"],
    "Repository": ["id", "databaseId", "name", "nameWithOwner", "owner",
                   "defaultBranchRef", "viewerPermission", "hasIssuesEnabled",
                   "issue", "issues", "pullRequests", "pullRequest", "url",
                   "description", "private", "fork", "createdAt"],
    "SearchType": None,  # enum
}

_GQL_ENUM_VALUES = {
    "SearchType": ["ISSUE", "PULL_REQUEST", "REPOSITORY", "USER", "DISCUSSION",
                   "COMMIT", "CODE"],
}


def _gql_validate(op, variables):
    """Walk the document against the schema; raise _GqlFieldError naming the
    first unknown field (message must name the field, e.g. the invalid-field
    check looks for 'noSuchFieldOnViewer')."""
    def walk(selection, type_name):
        fields = _GQL_SCHEMA.get(type_name)
        if fields is None:
            return
        for field in selection:
            if field.get("fragment"):
                walk(field["selection"], field["type"])
                continue
            name = field["name"]
            if name == "__typename":
                continue
            if name not in fields:
                raise _GqlFieldError(
                    'Cannot query field "%s" on type "%s".' % (name, type_name))
            child = _gql_child_type(type_name, name, field)
            if child and field.get("selection"):
                walk(field["selection"], child)

    root = "Mutation" if op["type"] == "mutation" else "Query"
    walk(op["selection"], root)


def _gql_child_type(parent, field_name, field):
    mapping = {
        ("Query", "viewer"): "User",
        ("Query", "repository"): "Repository",
        ("Query", "node"): "Node",
        ("Query", "__type"): "__Type",
        ("Repository", "owner"): "User",
        ("Repository", "defaultBranchRef"): "Ref",
        ("Repository", "issue"): "Issue",
        ("Repository", "issues"): "IssueConnection",
        ("Repository", "pullRequests"): "PullRequestConnection",
        ("Repository", "pullRequest"): "PullRequest",
        ("IssueConnection", "nodes"): "Issue",
        ("IssueConnection", "pageInfo"): "PageInfo",
        ("PullRequestConnection", "nodes"): "PullRequest",
        ("PullRequest", "files"): "PullRequestChangedFileConnection",
        ("PullRequestChangedFileConnection", "nodes"): "PullRequestChangedFile",
        ("Mutation", "createIssue"): "CreateIssuePayload",
        ("Mutation", "closeIssue"): "CloseIssuePayload",
        ("Mutation", "createPullRequest"): "CreatePullRequestPayload",
        ("Mutation", "mergePullRequest"): "MergePullRequestPayload",
        ("Mutation", "addComment"): "AddCommentPayload",
        ("CreateIssuePayload", "issue"): "Issue",
        ("CloseIssuePayload", "issue"): "Issue",
        ("CreatePullRequestPayload", "pullRequest"): "PullRequest",
        ("MergePullRequestPayload", "pullRequest"): "PullRequest",
        ("AddCommentPayload", "commentEdge"): "IssueCommentEdge",
        ("IssueCommentEdge", "node"): "IssueComment",
        ("__Type", "fields"): "__Field",
        ("__Type", "enumValues"): "__EnumValue",
    }
    return mapping.get((parent, field_name))


def _gql_execute(forge, op, variables):
    _gql_validate(op, variables)
    ctx = {"forge": forge, "variables": variables}
    if op["type"] == "mutation":
        return _gql_select(ctx, "Mutation", None, op["selection"])
    return _gql_select(ctx, "Query", None, op["selection"])


def _gql_select(ctx, type_name, parent, selection):
    out = {}
    for field in selection:
        if field.get("fragment"):
            # inline fragment: applies when the parent type matches
            if field["type"] == type_name or type_name == "Node":
                out.update(_gql_select(ctx, field["type"], parent,
                                       field["selection"]))
            continue
        value = _gql_field(ctx, type_name, parent, field)
        if field.get("selection") and isinstance(value, (dict, list)):
            value = _gql_nest(ctx, type_name, field, value)
        out[field["alias"]] = value
    return out


def _gql_nest(ctx, parent_type, field, value):
    child = _gql_child_type(parent_type, field["name"], field)
    if child is None or field.get("selection") is None:
        return value
    if isinstance(value, list):
        return [_gql_select(ctx, child, item, field["selection"])
                for item in value]
    if isinstance(value, dict):
        return _gql_select(ctx, child, value, field["selection"])
    return value


def _gql_args(ctx, field):
    return {k: _gql_resolve_value(v, ctx["variables"])
            for k, v in field["args"].items()}


def _gql_field(ctx, type_name, parent, field):
    forge = ctx["forge"]
    name = field["name"]
    args = _gql_args(ctx, field)

    if type_name == "Query":
        if name == "viewer":
            return {"__type": "User", "login": VIEWER_LOGIN}
        if name == "repository":
            repo = forge.get_repo(args.get("owner"), args.get("name"))
            return {"__type": "Repository", "_repo": repo} if repo else None
        if name == "node":
            decoded = gid_decode(args.get("id") or "")
            if not decoded:
                return None
            kind, parts = decoded
            if kind == "Repository" and parts:
                for repo in forge.list_repos():
                    if str(repo.id) == parts[0]:
                        return {"__type": "Repository", "_repo": repo}
            if kind == "Issue" and len(parts) >= 2:
                for repo in forge.list_repos():
                    if str(repo.id) == parts[0]:
                        issue = forge.find_issue(repo, int(parts[1]))
                        if issue:
                            return {"__type": "Issue", "_repo": repo,
                                    "_issue": issue}
            if kind == "PullRequest" and len(parts) >= 2:
                for repo in forge.list_repos():
                    if str(repo.id) == parts[0]:
                        pull = forge.find_pull(repo, int(parts[1]))
                        if pull:
                            return {"__type": "PullRequest", "_repo": repo,
                                    "_pull": pull}
            return None
        if name == "__type":
            return {"__type": "__Type", "_type_name": args.get("name")}
        raise _GqlFieldError('Cannot query field "%s" on type "Query".' % name)

    if type_name == "User":
        return VIEWER_LOGIN if name == "login" else None

    if type_name == "Repository":
        repo = parent["_repo"]
        if repo is None:
            return None
        if name == "id":
            return gid("Repository", repo.id)
        if name == "databaseId":
            return repo.id
        if name == "name":
            return repo.name
        if name == "nameWithOwner":
            return "%s/%s" % (repo.owner, repo.name)
        if name == "owner":
            return {"__type": "User", "login": repo.owner}
        if name == "defaultBranchRef":
            tip = repo.head_tip()
            if tip is None:
                return None
            return {"__type": "Ref", "name": repo.default_branch}
        if name == "viewerPermission":
            return "ADMIN"
        if name == "hasIssuesEnabled":
            return True
        if name == "issue":
            issue = forge.find_issue(repo, args.get("number"))
            return ({"__type": "Issue", "_repo": repo, "_issue": issue}
                    if issue else None)
        if name == "issues":
            return _gql_issue_connection(ctx, repo, args)
        if name == "pullRequests":
            pulls = list(repo.pulls)
            first = args.get("first")
            if first is not None:
                pulls = pulls[:first]
            return {"__type": "PullRequestConnection",
                    "_pulls": [{"__type": "PullRequest", "_repo": repo,
                                "_pull": p} for p in pulls]}
        if name == "pullRequest":
            pull = forge.find_pull(repo, args.get("number"))
            return ({"__type": "PullRequest", "_repo": repo, "_pull": pull}
                    if pull else None)
        return None

    if type_name == "Ref":
        return parent.get("name")

    if type_name == "Issue":
        issue = parent["_issue"]
        repo = parent["_repo"]
        if name == "id":
            return issue["gid"]
        if name == "number":
            return issue["number"]
        if name == "title":
            return issue["title"]
        if name == "state":
            return issue["state"].upper()
        if name == "body":
            return issue["body"]
        return None

    if type_name == "IssueConnection":
        return parent.get(name)

    if type_name == "PageInfo":
        return parent.get(name)

    if type_name == "PullRequest":
        pull = parent["_pull"]
        repo = parent["_repo"]
        if name == "id":
            return pull["gid"]
        if name == "number":
            return pull["number"]
        if name == "state":
            return pull["state"].upper()
        if name == "merged":
            return pull["merged"]
        if name == "headRefName":
            return pull["head"]
        if name == "baseRefName":
            return pull["base"]
        if name == "mergeable":
            return repo.mergeable_state(pull)
        if name == "files":
            files = repo.pull_files(pull)
            first = args.get("first")
            if first is not None:
                files = files[:first]
            return {"__type": "PullRequestChangedFileConnection",
                    "_files": [{"path": f["filename"]} for f in files]}
        return None

    if type_name == "PullRequestConnection":
        return parent.get("_pulls")

    if type_name == "PullRequestChangedFileConnection":
        return parent.get("_files")

    if type_name == "PullRequestChangedFile":
        return parent.get("path")

    if type_name == "Mutation":
        return _gql_mutation(ctx, name, args)

    if type_name == "__Type":
        type_name_arg = parent.get("_type_name")
        if name == "name":
            return type_name_arg
        if name == "fields":
            fields = _GQL_TYPE_FIELDS.get(type_name_arg)
            if fields is None:
                return []
            return [{"name": f} for f in fields]
        if name == "enumValues":
            values = _GQL_ENUM_VALUES.get(type_name_arg)
            if values is None:
                return []
            return [{"name": v} for v in values]
        return None

    if type_name in ("__Field", "__EnumValue"):
        return parent.get("name")

    if type_name in ("CreateIssuePayload", "CloseIssuePayload"):
        issue = parent.get("_issue")
        return ({"__type": "Issue", "_repo": parent.get("_repo"),
                 "_issue": issue} if issue else None)
    if type_name in ("CreatePullRequestPayload", "MergePullRequestPayload"):
        pull = parent.get("_pull")
        return ({"__type": "PullRequest", "_repo": parent.get("_repo"),
                 "_pull": pull} if pull else None)
    if type_name == "AddCommentPayload":
        return {"__type": "IssueCommentEdge",
                "_comment": parent.get("_comment")}
    if type_name == "IssueCommentEdge":
        comment = parent.get("_comment")
        return ({"__type": "IssueComment", "_comment": comment}
                if comment else None)
    if type_name == "IssueComment":
        comment = parent.get("_comment")
        if name == "id":
            return comment["gid"]
        if name == "body":
            return comment["body"]
        return None
    if type_name == "Node":
        concrete = parent.get("__type")
        if concrete and concrete != "Node":
            return _gql_field(ctx, concrete, parent, field)
        return parent.get(name)
    return None


def _gql_issue_connection(ctx, repo, args):
    issues = list(repo.issues)
    states = args.get("states")
    if states:
        wanted = {s.lower() for s in states}
        issues = [i for i in issues if i["state"] in wanted]
    order_by = args.get("orderBy") or {}
    direction = (order_by.get("direction") or "DESC").upper()
    issues.sort(key=lambda i: i["seq"], reverse=(direction == "DESC"))
    after = args.get("after")
    if after:
        decoded = gid_decode(after)
        if decoded and decoded[0] == "IssueCursor" and decoded[1]:
            try:
                cursor_number = int(decoded[1][0])
            except ValueError:
                cursor_number = None
            if cursor_number is not None:
                idx = None
                for pos, issue in enumerate(issues):
                    if issue["number"] == cursor_number:
                        idx = pos
                        break
                if idx is not None:
                    issues = issues[idx + 1:]
    first = args.get("first")
    has_next = False
    if first is not None:
        has_next = len(issues) > first
        issues = issues[:first]
    end_cursor = None
    if issues:
        end_cursor = gid("IssueCursor", issues[-1]["number"])
    nodes = [{"__type": "Issue", "_repo": repo, "_issue": i} for i in issues]
    return {"__type": "IssueConnection", "nodes": nodes,
            "pageInfo": {"hasNextPage": has_next, "endCursor": end_cursor}}


def _gql_mutation(ctx, name, args):
    forge = ctx["forge"]
    payload = args.get("input") or {}
    if name == "createIssue":
        decoded = gid_decode(payload.get("repositoryId") or "")
        repo = None
        if decoded and decoded[0] == "Repository" and decoded[1]:
            for candidate in forge.list_repos():
                if str(candidate.id) == decoded[1][0]:
                    repo = candidate
        if repo is None:
            raise _GqlFieldError("createIssue: repository not found")
        issue = forge.create_issue(repo, payload.get("title"),
                                   payload.get("body", ""), [])
        return {"__type": "CreateIssuePayload", "_repo": repo, "_issue": issue}
    if name == "closeIssue":
        decoded = gid_decode(payload.get("issueId") or "")
        issue = None
        repo = None
        if decoded and decoded[0] == "Issue" and len(decoded[1]) >= 2:
            for candidate in forge.list_repos():
                if str(candidate.id) == decoded[1][0]:
                    repo = candidate
                    issue = forge.find_issue(candidate, int(decoded[1][1]))
        if issue is None:
            raise _GqlFieldError("closeIssue: issue not found")
        issue["state"] = "closed"
        return {"__type": "CloseIssuePayload", "_repo": repo, "_issue": issue}
    if name == "createPullRequest":
        decoded = gid_decode(payload.get("repositoryId") or "")
        repo = None
        if decoded and decoded[0] == "Repository" and decoded[1]:
            for candidate in forge.list_repos():
                if str(candidate.id) == decoded[1][0]:
                    repo = candidate
        if repo is None:
            raise _GqlFieldError("createPullRequest: repository not found")
        try:
            pull = forge.create_pull(repo, payload.get("title"),
                                     payload.get("body", ""),
                                     payload.get("headRefName"),
                                     payload.get("baseRefName"))
        except Conflict as exc:
            raise _GqlFieldError(str(exc))
        return {"__type": "CreatePullRequestPayload", "_repo": repo,
                "_pull": pull}
    if name == "mergePullRequest":
        decoded = gid_decode(payload.get("pullRequestId") or "")
        pull = None
        repo = None
        if decoded and decoded[0] == "PullRequest" and len(decoded[1]) >= 2:
            for candidate in forge.list_repos():
                if str(candidate.id) == decoded[1][0]:
                    repo = candidate
                    pull = forge.find_pull(candidate, int(decoded[1][1]))
        if pull is None:
            raise _GqlFieldError("mergePullRequest: pull request not found")
        try:
            forge.merge_pull(repo, pull, "squash")
        except Conflict as exc:
            raise _GqlFieldError(str(exc))
        return {"__type": "MergePullRequestPayload", "_repo": repo,
                "_pull": pull}
    if name == "addComment":
        decoded = gid_decode(payload.get("subjectId") or "")
        issue = None
        repo = None
        if decoded and decoded[0] == "Issue" and len(decoded[1]) >= 2:
            for candidate in forge.list_repos():
                if str(candidate.id) == decoded[1][0]:
                    repo = candidate
                    issue = forge.find_issue(candidate, int(decoded[1][1]))
        if issue is None:
            raise _GqlFieldError("addComment: issue not found")
        comment = forge.add_comment(repo, issue, payload.get("body", ""))
        return {"__type": "AddCommentPayload", "_repo": repo,
                "_comment": comment}
    raise _GqlFieldError('Cannot query field "%s" on type "Mutation".' % name)


# ---------------------------------------------------------------------------
# Lifecycle: register with the env, poll /done, exit 0
# ---------------------------------------------------------------------------

def _http_json(url, method="GET", payload=None, timeout=30):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers,
                                     method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read()
        if not body:
            return {}
        return json.loads(body.decode("utf-8"))


def main():
    env_url = os.environ.get("MAKEFUN_ENV_URL", "").rstrip("/")
    if not env_url:
        port = int(os.environ.get("FORGE_PORT", "18080"))
        server = ForgeServer(("127.0.0.1", port))
        sys.stdout.write("[forge] standalone on http://127.0.0.1:%d\n" % port)
        sys.stdout.flush()
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        return 0

    server = ForgeServer(("0.0.0.0", 0))
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    sys.stdout.write("[forge] listening on port %d\n" % port)
    sys.stdout.flush()

    # register (retry with backoff; 200 or 409 means proceed)
    attempt = 0
    while True:
        try:
            _http_json(env_url + "/register", method="POST",
                       payload={"port": port})
            break
        except urllib.error.HTTPError as exc:
            if exc.code in (200, 409):
                break
            if exc.code in (400, 405):
                sys.stderr.write("[forge] register refused: HTTP %d\n" % exc.code)
                return 1
        except Exception:
            pass
        delay = min(2.0, 0.25 * (2 ** min(attempt, 3)))
        time.sleep(delay)
        attempt += 1
    sys.stdout.write("[forge] registered; waiting for done\n")
    sys.stdout.flush()

    # poll /done until true
    attempt = 0
    while True:
        try:
            result = _http_json(env_url + "/done")
            if result.get("done") is True:
                break
        except Exception:
            pass
        delay = min(2.0, 0.25 * (2 ** min(attempt, 3)))
        time.sleep(delay)
        attempt += 1
    server.shutdown()
    server.server_close()
    sys.stdout.write("[forge] done\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
