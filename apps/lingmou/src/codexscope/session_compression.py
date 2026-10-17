"""Conversation-scoped, append-only rendering of compressed requests.

Provider prompt caches match an exact prefix. Deciding again on every request
how old history is rendered (task-dependent excerpts, one more archived output
per request) moved the first changed item toward the start of the request and
turned cached input into full-price input. This ledger:

* freezes the first rendering of every history item and of the instructions /
  tool definitions, so a conversation's sent prefix only grows by appending;
* performs lossy history work (stale-output supersession, archiving old tool
  output, old screenshots, whole old turns) only at explicit checkpoints, with
  a high/low watermark, and only when the estimated cache-break cost is repaid;
* records where each request's sent prefix diverged from the previous request
  of the same conversation, and whether Lingmou or the client caused it.

All numbers are local estimates. Official cached-token usage is fed back with
`observe_usage` and only changes the checkpoint economics, never the request.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import threading
from collections import OrderedDict, deque
from dataclasses import dataclass, field

from token_compression.history import trim_history

from .structural_compression import dumps
from .tool_output_history import (PINNED_READ, archive_notice, archived, compact_tool_outputs,
                                  failed_output, tool_text_slots)

_HEADER_FIELDS = ('tools', 'functions', 'instructions', 'tool_choice')
_RESULTS = {'function_call_output', 'custom_tool_call_output'}
_CALLS = {'function_call', 'custom_tool_call'}
_IMAGES = {'input_image', 'image_url'}
_OPAQUE = re.compile(r'"data:[A-Za-z0-9.+/-]+;base64,[A-Za-z0-9+/=\\]*"|("encrypted_content":\s*)"[^"]*"')
_MISSING = object()
_IMAGE_NOTICE = ('[Earlier image removed by Lingmou to save context. Re-open or re-capture it '
                 'if its details are needed again.]')


def media_free(count):
    """Count serialized JSON without inline media and opaque encrypted state.

    Providers bill images by resolution and do not bill encrypted reasoning as
    its ciphertext; counting their base64 text inflated every estimate.
    """
    return lambda text: count(_OPAQUE.sub(lambda m: (m[1] or '') + '""', text))


def _digest(value) -> str:
    return hashlib.sha256(dumps(value).encode()).hexdigest()


def _items_key(body):
    return 'messages' if 'messages' in body else 'input'


def _metadata_thread(body):
    metadata = body.get('client_metadata')
    if not isinstance(metadata, dict):
        return None
    nested = metadata.get('x-codex-turn-metadata')
    if isinstance(nested, str) and len(nested) < 100_000:
        try:
            value = json.loads(nested)
            metadata = {**metadata, **value} if isinstance(value, dict) else metadata
        except ValueError:
            pass
    for name in ('thread_id', 'session_id'):
        value = metadata.get(name)
        if isinstance(value, str) and 0 < len(value) <= 128:
            return value
    return None


def session_key(body: dict, mode: str = '') -> str:
    """Thread metadata, else prompt_cache_key, else the first history item."""
    identity = _metadata_thread(body)
    if identity is None and isinstance(body.get('prompt_cache_key'), str):
        identity = 'cache:' + body['prompt_cache_key']
    if identity is None:
        items = body.get(_items_key(body))
        first = items[0] if isinstance(items, list) and items else items
        identity = 'first:' + _digest([body.get('instructions'), first])
    return hashlib.sha256((mode + '\0' + identity).encode()).hexdigest()[:24]


def _chain(items):
    result, previous = [], ''
    for item in items:
        previous = hashlib.sha256((previous + '\0' + dumps(item)).encode()).hexdigest()
        result.append(previous)
    return result


@dataclass(frozen=True)
class SessionConfig:
    tool_checkpoint_tokens: int = 40000
    tool_target_tokens: int = 12000
    keep_tool_results: int = 4
    history_trigger_tokens: int = 96000
    history_target_tokens: int = 48000
    history_keep_turns: int = 2
    keep_recent_images: int = 2
    image_batch: int = 3
    supersede_stale_outputs: bool = True
    archive_tool_call_inputs: bool = False
    # Minimum length of an archived call input; writes/patches only unless
    # archive_any_call_input also pages long scripts and commands.
    call_input_min_chars: int = 4000
    archive_any_call_input: bool = False
    archive_min_chars: int = 1600
    archive_head_chars: int = 600
    archive_tail_chars: int = 400
    archive_min_saved: int = 256
    # False checkpoints whenever a watermark is crossed, ignoring cache cost.
    cache_economics: bool = True
    cache_price_ratio: float = .1
    min_future_requests: int = 4
    max_future_requests: int = 40
    pressure_tokens: int = 160000
    max_sessions: int = 32

    @classmethod
    def from_env(cls):
        values = {}
        for name, item in cls.__dataclass_fields__.items():
            raw = os.environ.get('LINGMOU_SESSION_' + name.upper())
            if raw is not None:
                values[name] = (raw.lower() in {'1', 'true', 'yes'} if isinstance(item.default, bool)
                                else type(item.default)(raw))
        return cls(**values)


# Desktop `max`: compression rate first. Checkpoints run at low watermarks on
# every crossing regardless of cache cost; most lossy steps stay recoverable.
MAX_SESSION = SessionConfig(
    tool_checkpoint_tokens=6000, tool_target_tokens=2500, keep_tool_results=2,
    history_trigger_tokens=24000, history_target_tokens=12000, history_keep_turns=1,
    keep_recent_images=1, image_batch=1, archive_tool_call_inputs=True,
    call_input_min_chars=1200, archive_any_call_input=True, archive_min_chars=800,
    archive_head_chars=200, archive_tail_chars=200, archive_min_saved=64, cache_economics=False)


@dataclass
class _Session:
    renders: dict = field(default_factory=dict)
    headers: dict = field(default_factory=dict)
    token_cache: OrderedDict = field(default_factory=OrderedDict)
    last_header: str | None = None
    last_header_origin: str | None = None
    last_items: list = field(default_factory=list)
    last_origin: list = field(default_factory=list)
    requests: int = 0
    checkpoints: int = 0
    declined_checkpoints: int = 0
    breaks: dict = field(default_factory=lambda: {'lingmou': 0, 'client': 0})
    cached: deque = field(default_factory=lambda: deque(maxlen=6))


# ---------------------------------------------------------------- checkpoint policies

_READ = re.compile(r'(?i)(?:\b(?:cat|type|head|tail|less|more|nl|bat|Get-Content|gc|sed\s+-n|rg|grep|findstr|'
                   r'Select-String|read_file|view_file|open_file)\b|\bread\b)')
_PATCH_FILE = re.compile(r'^\*\*\* (?:Update|Add|Delete) File: (.+?)\s*$|^\*\*\* Move to: (.+?)\s*$', re.M)
_SHELL_WRITE = re.compile(r'(?:>>?|\b(?:Set-Content|Add-Content|Out-File|tee)\b(?:\s+-\w+)*)\s+[\'"]?([^\s\'"|;&)]+)')
_PATH_KEYS = ('path', 'file_path', 'filepath', 'filename', 'target_file')


def _calls(items):
    calls = {}
    for index, item in enumerate(items):
        if item.get('type') in _CALLS:
            raw = item.get('arguments', item.get('input'))
            calls.setdefault(item.get('call_id'), []).append((index, item.get('name', ''), raw if isinstance(raw, str) else dumps(raw)))
        for call in item.get('tool_calls', []) or []:
            if isinstance(call, dict) and isinstance(call.get('function'), dict):
                function = call['function']
                calls.setdefault(call.get('id'), []).append((index, function.get('name', ''), str(function.get('arguments', ''))))
    return {key: value[0] for key, value in calls.items() if isinstance(key, str) and len(value) == 1}


def _written_paths(name, text):
    paths = {match[1] or match[2] for match in _PATCH_FILE.finditer(text)}
    paths.update(_SHELL_WRITE.findall(text))
    if re.search(r'(?i)write|edit|create|save', name):
        try:
            value = json.loads(text)
        except ValueError:
            value = None
        if isinstance(value, dict):
            paths.update(v for k, v in value.items() if k in _PATH_KEYS and isinstance(v, str))
    return {path.strip().replace('\\', '/') for path in paths if path and len(path.strip()) >= 3}


def _results(items):
    rows = []
    for index, item in enumerate(items):
        if item.get('type') in _RESULTS or item.get('role') == 'tool':
            rows.append((index, item.get('call_id', item.get('tool_call_id')), item))
    return rows


def supersede_stale_outputs(items, *, sources, count, store, keep_last=1):
    """Archive outputs that a later identical call or a later file write made stale.

    The archive is exact and rereadable; the notice names the newer call.
    """
    calls = _calls(items)
    results = _results(items)
    output_ids = {}
    for _, call_id, _ in results:
        output_ids[call_id] = output_ids.get(call_id, 0) + 1
    usable = [(index, call_id, item) for index, call_id, item in results
              if call_id in calls and output_ids[call_id] == 1 and calls[call_id][0] < index]
    protected = {call_id for _, call_id, _ in usable[-keep_last:]} if keep_last else set()
    latest_signature, writes = {}, []
    for index, call_id, _ in usable:
        _, name, text = calls[call_id]
        latest_signature[(name, ' '.join(text.split()))] = call_id
        if paths := _written_paths(name, text):
            writes.append((calls[call_id][0], call_id, paths))
    changed = 0
    for index, call_id, item in usable:
        if call_id in protected:
            continue
        call_index, name, text = calls[call_id]
        newer = latest_signature.get((name, ' '.join(text.split())))
        reason = 'same_call_repeated' if newer not in (None, call_id) else None
        if reason is None and _READ.search(name + ' ' + text) and not PINNED_READ.search(text):
            normalized = text.replace('\\', '/')
            for write_index, write_id, paths in writes:
                if write_index > call_index and write_id != call_id and any(p in normalized for p in paths):
                    newer, reason = write_id, 'file_modified_later'
                    break
        if reason is None:
            continue
        for container, key in tool_text_slots(item):
            current = container[key]
            source = sources.get((id(container), key), current)
            if archived(current) or '$lingmou' in source or len(source) < 600:
                continue
            notice = archive_notice(source, store=store, count=count, notice_kind='superseded/v1',
                extra={'superseded_by': newer, 'reason': reason}, min_ratio=.2, min_saved=64,
                head_chars=200, tail_chars=200, current_tokens=count(current))
            if notice is not None:
                container[key] = notice
                changed += 1
    return changed


def archive_old_images(items, *, keep_recent):
    """Replace older screenshots with a short notice. Latest user images stay."""
    latest_user = max((i for i, item in enumerate(items) if item.get('role') == 'user'), default=-1)
    parts = []
    for index, item in enumerate(items):
        for key in ('content', 'output'):
            value = item.get(key)
            if isinstance(value, list):
                parts.extend((index, part) for part in value
                             if isinstance(part, dict) and part.get('type') in _IMAGES)
    candidates = parts[:-keep_recent] if keep_recent else parts
    changed = 0
    for index, part in candidates:
        if index == latest_user:
            continue
        kind = 'text' if part.get('type') == 'image_url' else 'input_text'
        part.clear()
        part.update(type=kind, text=_IMAGE_NOTICE)
        changed += 1
    return changed, len(candidates)


def archive_tool_call_inputs(items, *, count, store, keep_last, min_chars=4000, any_call=False):
    """Opt-in: archive large, old, successful call inputs (patches/writes by default)."""
    calls = _calls(items)
    results = {call_id: item for _, call_id, item in _results(items)}
    ordered = [call_id for call_id in calls if call_id in results]
    changed = 0
    for call_id in ordered[:-keep_last] if keep_last else ordered:
        index, name, text = calls[call_id]
        item = items[index]
        if (item.get('type') != 'custom_tool_call' or len(text) < min_chars
                or not (any_call or _written_paths(name, text)) or PINNED_READ.search(text)
                or any(failed_output(c[k]) for c, k in tool_text_slots(results[call_id]))):
            continue
        try:
            source_id = store.put(text)
        except (ValueError, OSError):
            continue
        headers = '\n'.join(line for line in text.splitlines() if line.startswith('*** '))
        candidate = (f'[Lingmou archived this applied input; lingmou_source_read(source_id="{source_id}",'
                     f'start_line=1,end_line={len(text.splitlines())}) recovers it exactly.]\n{headers}')
        if count(candidate) < count(text) * .5:
            item['input'] = candidate
            changed += 1
    return changed


# ---------------------------------------------------------------- ledger

class SessionCompressionLedger:
    def __init__(self, config: SessionConfig | None = None):
        self.config = config or SessionConfig.from_env()
        self._sessions: OrderedDict[str, _Session] = OrderedDict()
        self._lock = threading.Lock()
        self.totals = {'requests': 0, 'checkpoints': 0, 'declined_checkpoints': 0,
                       'prefix_breaks_lingmou': 0, 'prefix_breaks_client': 0}

    def stats(self):
        with self._lock:
            return dict(self.totals, sessions=len(self._sessions))

    def observe_usage(self, key, usage):
        """Feed back official usage; only changes the cache-break economics."""
        if not key or not isinstance(usage, dict):
            return
        cached, total = usage.get('cached_input_tokens'), usage.get('input_tokens')
        if type(cached) is not int or type(total) is not int:
            return
        with self._lock:
            if (session := self._sessions.get(key)) is not None:
                session.cached.append((total, cached))

    def _session(self, key):
        session = self._sessions.get(key)
        if session is None:
            session = self._sessions[key] = _Session()
        self._sessions.move_to_end(key)
        while len(self._sessions) > self.config.max_sessions:
            self._sessions.popitem(last=False)
        return session

    def _tokens(self, session, item, count):
        digest = _digest(item)
        value = session.token_cache.get(digest)
        if value is None:
            value = session.token_cache[digest] = count(dumps(item))
            while len(session.token_cache) > 8192:
                session.token_cache.popitem(last=False)
        return value

    def apply(self, original, compressed, *, count, mode='', store=None, checkpoint=False, freeze=True):
        """Return (body to send, diagnostics). Never raises for unfamiliar shapes."""
        count = media_free(count)
        key = session_key(original, mode)
        name = _items_key(original)
        o_items, c_items = original.get(name), compressed.get(name)
        with self._lock:
            session = self._session(key)
            session.requests += 1
            self.totals['requests'] += 1
            shaped = (isinstance(o_items, list) and isinstance(c_items, list) and len(o_items) == len(c_items)
                      and all(isinstance(x, dict) for x in o_items + c_items))
            body = copy.copy(compressed)
            info = {'session': key, 'request': session.requests, 'stabilized': bool(freeze and shaped),
                    'reused_items': 0, 'new_items': 0, 'checkpoint': None}
            origin = _chain(o_items) if isinstance(o_items, list) and all(isinstance(x, dict) for x in o_items) else []
            if freeze and shaped:
                for name_ in _HEADER_FIELDS:
                    if name_ not in original:
                        continue
                    header = name_ + ':' + _digest(original[name_])
                    if header in session.headers:
                        value = session.headers[header]
                        if value is _MISSING:
                            body.pop(name_, None)
                        else:
                            body[name_] = copy.deepcopy(value)
                    else:
                        session.headers[header] = copy.deepcopy(compressed.get(name_, _MISSING))
                rendered, owners = [], []
                for index, (fp, raw, sent) in enumerate(zip(origin, o_items, c_items)):
                    if fp in session.renders:
                        frozen = session.renders[fp]
                        items = [copy.deepcopy(raw)] if frozen is None else copy.deepcopy(frozen)
                        info['reused_items'] += 1
                    else:
                        items = [copy.deepcopy(sent)]
                        session.renders[fp] = None if sent == raw else copy.deepcopy(items)
                        info['new_items'] += 1
                    rendered.extend(items)
                    owners.extend([index] * len(items))
                body[name] = rendered
                if checkpoint and store is not None:
                    done = self._checkpoint(session, body, owners, o_items, count=count, store=store)
                    if done is not None:
                        info['checkpoint'], rendered, owners = done
                        body[name] = rendered
                        for index, fp in enumerate(origin):
                            items = [item for item, owner in zip(rendered, owners) if owner == index]
                            session.renders[fp] = None if items == [o_items[index]] else copy.deepcopy(items)
            info.update(self._diagnose(session, body, original, origin, count))
            return body, info

    def _diagnose(self, session, body, original, origin, count):
        name = _items_key(body)
        items = body.get(name) if isinstance(body.get(name), list) else []
        header = _digest({k: body.get(k) for k in _HEADER_FIELDS if k in body})
        header_origin = _digest({k: original.get(k) for k in _HEADER_FIELDS if k in original})
        digests = [_digest(item) for item in items]
        header_tokens = count(dumps({k: body.get(k) for k in _HEADER_FIELDS if k in body}))
        result = {'previous_items': len(session.last_items), 'header_stable': None,
                  'common_prefix_items': 0, 'prefix_tokens_estimate': 0, 'break': None}
        if session.last_header is not None:
            result['header_stable'] = header == session.last_header
            common = 0
            if result['header_stable']:
                for old, new in zip(session.last_items, digests):
                    if old != new:
                        break
                    common += 1
            result['common_prefix_items'] = common
            if result['header_stable']:
                result['prefix_tokens_estimate'] = header_tokens + sum(
                    self._tokens(session, item, count) for item in items[:common])
            broken = not result['header_stable'] or common < len(session.last_items)
            if broken:
                origin_common = 0
                for old, new in zip(session.last_origin, origin):
                    if old != new:
                        break
                    origin_common += 1
                if not result['header_stable']:
                    cause = 'lingmou' if header_origin == session.last_header_origin else 'client'
                    where = 'header'
                else:
                    # Rendered items are not 1:1 with origins after a checkpoint;
                    # if the client still sent the whole previous history, the
                    # change is ours.
                    cause = 'lingmou' if origin_common >= len(session.last_origin) else 'client'
                    where = 'item'
                result['break'] = {'where': where, 'index': common, 'cause': cause,
                    'tokens_after_break_estimate': sum(self._tokens(session, item, count) for item in items[common:])}
                session.breaks[cause] += 1
                self.totals['prefix_breaks_' + cause] += 1
        session.last_header, session.last_header_origin = header, header_origin
        session.last_items, session.last_origin = digests, origin
        result['session_breaks'] = dict(session.breaks)
        return result

    def _cache_ratio(self, session):
        if len(session.cached) >= 2 and all(cached == 0 for _, cached in session.cached):
            return None  # No caching observed: breaking a prefix costs nothing extra.
        return self.config.cache_price_ratio

    def _checkpoint(self, session, body, owners, o_items, *, count, store):
        config = self.config
        name = _items_key(body)
        working = copy.deepcopy(body)
        items = working[name]
        sources = {}
        for item, owner in zip(items, owners):
            if item.get('type') in _RESULTS or item.get('role') == 'tool':
                sent, raw = list(tool_text_slots(item)), list(tool_text_slots(o_items[owner]))
                if len(sent) == len(raw):
                    for (container, key), (source, source_key) in zip(sent, raw):
                        sources[(id(container), key)] = source[source_key]
        tool_tokens = sum(count(c[k]) for item in items for c, k in tool_text_slots(item)
                          if item.get('type') in _RESULTS or item.get('role') == 'tool')
        if config.archive_tool_call_inputs:
            # Archivable call inputs (scripts, patches) count toward the same watermark.
            tool_tokens += sum(count(item['input']) for item in items
                               if item.get('type') == 'custom_tool_call' and isinstance(item.get('input'), str))
        context = count(dumps(working))
        _, old_images = archive_old_images(copy.deepcopy(items), keep_recent=config.keep_recent_images)
        triggers = [reason for reason, active in (
            ('tool_output', tool_tokens > config.tool_checkpoint_tokens),
            ('images', old_images >= config.image_batch),
            ('history', context > config.history_trigger_tokens)) if active]
        if not triggers:
            return None
        before_items = copy.deepcopy(items)
        before_digests = [_digest(item) for item in before_items]
        steps = {}
        if config.supersede_stale_outputs:
            steps['superseded_outputs'] = supersede_stale_outputs(items, sources=sources, count=count, store=store)
        steps['archived_outputs'] = compact_tool_outputs(working, budget=config.tool_target_tokens,
            keep_results=config.keep_tool_results, count=count, store=store, sources=sources,
            min_chars=config.archive_min_chars, head_chars=config.archive_head_chars,
            tail_chars=config.archive_tail_chars, min_saved=config.archive_min_saved)
        steps['archived_images'], _ = archive_old_images(items, keep_recent=config.keep_recent_images)
        if config.archive_tool_call_inputs:
            steps['archived_call_inputs'] = archive_tool_call_inputs(items, count=count, store=store,
                keep_last=config.keep_tool_results, min_chars=config.call_input_min_chars,
                any_call=config.archive_any_call_input)
        new_owners = list(owners)
        if count(dumps(working)) > config.history_trigger_tokens:
            try:
                trimmed, archive = trim_history(working, original_body=working,
                    budget=config.history_target_tokens, keep_turns=config.history_keep_turns,
                    count=count, store=store, archive_notice=True)
            except (ValueError, OSError):
                archive = None
            if archive:
                prefix = next(i for i, item in enumerate(items) if item.get('role') == 'user')
                removed = archive['removed_messages']
                new_owners = owners[:prefix] + [owners[prefix]] + owners[prefix + removed:]
                working = trimmed
                steps['archived_messages'] = removed
        after_items = working[name]
        after = count(dumps(working))
        if not any(steps.values()) or after >= context:
            return None
        first = next((i for i, (old, new) in enumerate(zip(before_digests, map(_digest, after_items)))
                      if old != new), min(len(before_digests), len(after_items)))
        # Tokens that were going to be cache hits (sent in the previous request
        # with an unchanged prefix) and are now billed at full price once.
        reusable = 0
        for i, digest in enumerate(before_digests[first:], first):
            if i >= len(session.last_items) or session.last_items[i] != digest:
                break
            reusable += self._tokens(session, before_items[i], count)
        ratio = self._cache_ratio(session)
        saved = context - after
        future = max(config.min_future_requests, min(config.max_future_requests, session.requests))
        if ratio is None:
            cost, benefit = 0, saved * future
        else:
            cost = int(reusable * (1 - ratio))
            benefit = int(saved * ratio * future)
        pressure = context >= config.pressure_tokens
        info = {'triggers': triggers, **steps, 'context_before_estimate': context,
                'context_after_estimate': after, 'saved_estimate': saved,
                'first_changed_item': first, 'break_cost_estimate': cost,
                'benefit_estimate': benefit, 'expected_future_requests': future,
                'cache_price_ratio': ratio, 'pressure': pressure}
        if config.cache_economics and not pressure and benefit < cost:
            session.declined_checkpoints += 1
            self.totals['declined_checkpoints'] += 1
            return None
        session.checkpoints += 1
        self.totals['checkpoints'] += 1
        return {**info, 'performed': True}, after_items, new_owners
