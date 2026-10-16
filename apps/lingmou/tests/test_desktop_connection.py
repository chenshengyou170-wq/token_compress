"""Provider identity must survive connect, exit, crash and legacy upgrades.

All configurations and credentials in these tests are synthetic.
"""
import hashlib
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest
import tomlkit

from codexscope.desktop_connection import (
    API_UPSTREAM, CHATGPT_UPSTREAM, CodexConnection, ConnectionError, file_lock, inspect_codex,
)
from codexscope.request_token_tap import RequestTokenTap
from codexscope.storage import atomic_json_dump


def prepare(tmp_path, original='', auth_kind='chatgpt'):
    target = tmp_path / 'config.toml'
    target.write_text(original, encoding='utf-8')
    connection = CodexConnection(tmp_path / 'state')
    connection.prepare(path=str(target), auth_kind=auth_kind, upstream='', mode='off',
                       source_command=sys.executable, source_args=['sources'])
    return connection, target


@pytest.mark.parametrize('auth_kind,upstream', [('chatgpt', CHATGPT_UPSTREAM), ('api', API_UPSTREAM)])
@pytest.mark.parametrize('selection', ['', 'model_provider = "openai"\n'])
def test_new_threads_keep_builtin_identity_after_disconnect(tmp_path, auth_kind, upstream, selection):
    original = '# User preferences\n' + selection + 'model = "test"\n'
    connection, target = prepare(tmp_path, original, auth_kind)
    connection.apply(12345)
    connected = tomlkit.parse(target.read_text())
    # This is the identity Codex stores in its rollout and thread index.
    persisted_thread_provider = connected.get('model_provider', 'openai')
    assert persisted_thread_provider == 'openai'
    assert 'model_providers' not in connected
    assert connected['openai_base_url'].startswith('http://127.0.0.1:12345/lingmou-relay/')
    assert connection.record['upstream'] == upstream
    assert connection.record['access_token'] not in json.dumps(connection.public())
    connection.restore()
    assert target.read_text() == original
    assert tomlkit.parse(target.read_text()).get('model_provider', 'openai') == persisted_thread_provider


def test_builtin_existing_upstream_is_used_and_restored(tmp_path):
    original = 'openai_base_url = "https://gateway.example/v1"\n'
    connection, target = prepare(tmp_path, original, 'existing')
    assert connection.record['upstream'] == 'https://gateway.example/v1'
    assert inspect_codex(str(target))['upstream'] == 'https://gateway.example/v1'
    connection.apply(12345)
    connection.restore()
    assert target.read_text() == original


@pytest.mark.parametrize('original', [
    '',
    '[features]\ncode_mode = true\n',
    '[features]\ncode_mode = false\n',
    '[features.code_mode]\nenabled = false\ndirect_only_tool_namespaces = ["existing_tool"]\n',
])
def test_reader_is_directly_advertised_and_code_mode_preferences_restore(tmp_path, original):
    connection, target = prepare(tmp_path, original)
    connection.apply(12345)
    connected = tomlkit.parse(target.read_text())
    mode = connected['features']['code_mode']
    reader = 'mcp__' + connection.record['source_server']
    assert len(reader + '__lingmou_source_read') <= 64
    assert reader in mode['direct_only_tool_namespaces']
    if 'existing_tool' in original:
        assert mode['direct_only_tool_namespaces'] == ['existing_tool', reader]
    if 'false' in original:
        assert mode['enabled'] is False
    elif 'true' in original:
        assert mode['enabled'] is True
    connected['model'] = 'user-changed-model'
    target.write_text(tomlkit.dumps(connected))
    CodexConnection(connection.root).restore()
    expected = tomlkit.parse(original)
    expected['model'] = 'user-changed-model'
    assert tomlkit.parse(target.read_text()) == expected


def test_reader_pin_restoration_preserves_other_code_mode_edits(tmp_path):
    connection, target = prepare(tmp_path)
    connection.apply(12345)
    connected = tomlkit.parse(target.read_text())
    connected['features']['code_mode']['excluded_tool_namespaces'] = ['other_tool']
    target.write_text(tomlkit.dumps(connected))
    connection.restore()
    assert tomlkit.parse(target.read_text()) == {
        'features': {'code_mode': {'excluded_tool_namespaces': ['other_tool']}}}


def test_changed_direct_tool_list_blocks_restore_without_losing_user_edits(tmp_path):
    connection, target = prepare(tmp_path)
    connection.apply(12345)
    connected = tomlkit.parse(target.read_text())
    connected['features']['code_mode']['direct_only_tool_namespaces'].append('user_added_tool')
    edited = tomlkit.dumps(connected)
    target.write_text(edited)
    with pytest.raises(ConnectionError, match='direct_only_tool_namespaces'):
        connection.restore()
    assert target.read_text() == edited


@pytest.mark.parametrize('original', [
    'model_provider = "company"\n[model_providers.company]\nname = "Company"\n'
    'base_url = "https://gateway.example/v1"\nenv_key = "COMPANY_API_KEY"\n',
    'model_provider = "company"\n[model_providers.company]\nname = "Company"\n'
    'base_url = "https://gateway.example/v1"\nrequires_openai_auth = true\n'
    '[model_providers.company.http_headers]\nX-Company = "synthetic-header"\n'
    '[model_providers.company.env_http_headers]\nX-Project = "COMPANY_PROJECT"\n',
])
def test_custom_identity_auth_and_unrelated_edits_survive(tmp_path, original):
    connection, target = prepare(tmp_path, original, 'existing')
    before = tomlkit.parse(original)
    connection.apply(12345)
    connected = tomlkit.parse(target.read_text())
    assert connected['model_provider'] == 'company'
    provider = connected['model_providers']['company']
    for key in ('env_key', 'requires_openai_auth', 'env_http_headers'):
        assert provider.get(key) == before['model_providers']['company'].get(key)
    provider['request_max_retries'] = 7
    connected['model'] = 'user-changed-model'
    target.write_text(tomlkit.dumps(connected))
    CodexConnection(connection.root).restore()
    restored = tomlkit.parse(target.read_text())
    expected = tomlkit.parse(original)
    expected['model'] = 'user-changed-model'
    expected['model_providers']['company']['request_max_retries'] = 7
    assert restored.unwrap() == expected.unwrap()


def test_changing_default_while_connected_is_not_undone(tmp_path):
    connection, target = prepare(tmp_path)
    connection.apply(12345)
    connected = tomlkit.parse(target.read_text())
    connected['model_provider'] = 'user-selected-provider'
    target.write_text(tomlkit.dumps(connected))
    connection.restore()
    assert tomlkit.parse(target.read_text()) == {'model_provider': 'user-selected-provider'}


def test_changed_routing_field_blocks_restore_without_overwriting_user_config(tmp_path):
    connection, target = prepare(tmp_path)
    connection.apply(12345)
    edited = target.read_text().replace('127.0.0.1:12345', '127.0.0.1:54321')
    target.write_text(edited)
    with pytest.raises(ConnectionError, match='openai_base_url'):
        connection.restore()
    assert target.read_text() == edited and connection.enabled


def test_another_installation_cannot_nest_the_builtin_route(tmp_path):
    connection, target = prepare(tmp_path)
    connection.apply(12345)
    with pytest.raises(ConnectionError, match='已接入'):
        inspect_codex(str(target))
    other = CodexConnection(tmp_path / 'other-state')
    with pytest.raises(ConnectionError, match='已接入'):
        other.prepare(path=str(target), auth_kind='chatgpt', upstream='', mode='off',
                      source_command=sys.executable, source_args=[])


def test_unauthenticated_chatgpt_custom_provider_is_not_reused(tmp_path):
    original = ('model_provider = "openai_http"\n[model_providers.openai_http]\n'
                'name = "OpenAI HTTP only"\nbase_url = "' + CHATGPT_UPSTREAM + '"\n')
    with pytest.raises(ConnectionError, match='requires_openai_auth'):
        prepare(tmp_path, original, 'existing')
    assert (tmp_path / 'config.toml').read_text() == original


def legacy_connection(tmp_path, original='model = "test"\n'):
    """A v0.1.1 journal/config, including the provider saved by old threads."""
    target = tmp_path / 'config.toml'
    root = tmp_path / 'state'
    directory = root / 'connections' / 'old-test-connection'
    directory.mkdir(parents=True)
    alias = 'lingmou_desktop_oldtest'
    source = 'lingmou_desktop_sources_oldtest'
    before = tomlkit.parse(original)
    applied = tomlkit.parse(original)
    applied['model_provider'] = alias
    applied.setdefault('model_providers', {})[alias] = {
        'name': 'Lingmou local compression', 'requires_openai_auth': True,
        'base_url': 'http://127.0.0.1:12345/backend-api/codex',
        'http_headers': {'X-Lingmou-Relay-Token': 'synthetic-old-relay-token'},
    }
    applied['mcp_servers'] = {source: {'command': 'python', 'args': ['sources']}}
    applied['features'] = {'enable_request_compression': False}
    target.write_text(tomlkit.dumps(applied))
    (directory / 'original.toml').write_text(original)
    (directory / 'applied.toml').write_text(tomlkit.dumps(applied))
    atomic_json_dump(root / 'connection.json', {
        'version': 1, 'id': 'old-test-connection', 'phase': 'connected',
        'config_path': str(target), 'config_existed': True,
        'original_digest': hashlib.sha256(original.encode()).hexdigest(),
        'original_provider': before.get('model_provider', 'openai'), 'provider': alias,
        'auth_kind': 'chatgpt', 'upstream': CHATGPT_UPSTREAM,
        'source_server': source, 'port': 12345, 'mode': 'off',
    })
    return CodexConnection(root), target, alias


def test_legacy_exit_keeps_historical_provider_resolvable_and_authenticated(tmp_path):
    connection, target, saved_thread_provider = legacy_connection(tmp_path)
    connection.restore()
    restored = tomlkit.parse(target.read_text())
    assert restored.get('model_provider', 'openai') == 'openai'
    provider = restored['model_providers'][saved_thread_provider]
    assert provider['name'] == 'OpenAI' and provider['requires_openai_auth'] is True
    assert provider['base_url'] == CHATGPT_UPSTREAM
    assert 'http_headers' not in provider and 'mcp_servers' not in restored
    assert connection.public()['legacy_provider_preserved']
    assert not connection.enabled


def test_legacy_custom_provider_restores_its_own_auth_not_openai(tmp_path):
    original = ('model_provider = "company"\n[model_providers.company]\nname = "Company"\n'
                'base_url = "https://gateway.example/v1"\nenv_key = "COMPANY_API_KEY"\n')
    connection, target, alias = legacy_connection(tmp_path, original)
    connection.recover()
    restored = tomlkit.parse(target.read_text())
    assert restored['model_provider'] == 'company'
    assert restored['model_providers'][alias] == restored['model_providers']['company']
    assert not connection.enabled


def test_upgrade_repairs_provider_already_deleted_by_old_version(tmp_path):
    connection, target, alias = legacy_connection(tmp_path)
    # v0.1.1 exited, then the user changed their default; only our missing
    # historical alias may be added back, without rolling back those changes.
    target.write_text('model_provider = "company"\nmodel = "new-model"\n')
    connection.record['phase'] = 'disconnected'
    connection._save()
    connection.recover()
    restored = tomlkit.parse(target.read_text())
    assert restored['model_provider'] == 'company' and restored['model'] == 'new-model'
    assert restored['model_providers'][alias]['requires_openai_auth'] is True
    assert not connection.enabled
    before = target.read_bytes()
    CodexConnection(connection.root).recover()
    assert target.read_bytes() == before


def test_interrupted_legacy_restore_is_idempotent(tmp_path, monkeypatch):
    connection, target, alias = legacy_connection(tmp_path)
    save = connection._save
    def fail_after_config_write():
        if connection.record['phase'] == 'disconnected':
            raise OSError('simulated power failure before final journal save')
        save()
    monkeypatch.setattr(connection, '_save', fail_after_config_write)
    with pytest.raises(OSError):
        connection.restore()
    first = target.read_bytes()
    reopened = CodexConnection(connection.root)
    reopened.recover()
    assert not reopened.enabled
    assert target.read_bytes() == first
    assert alias in tomlkit.parse(target.read_text())['model_providers']


def test_abandoned_lock_file_does_not_block_next_owner(tmp_path):
    lock = tmp_path / '.config.toml.lingmou.lock'
    lock.write_bytes(b'\0')
    with file_lock(lock):
        pass
    with file_lock(lock):
        pass


def test_relay_preserves_upstream_auth_and_handles_builtin_websocket_fallback(tmp_path):
    received = []
    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_POST(self):
            received.append((self.path, dict(self.headers), self.rfile.read(int(self.headers['Content-Length']))))
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"ok":true}')
    server = ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    token = 'synthetic_local_capability_' + 'x' * 32
    tap = RequestTokenTap(f'http://127.0.0.1:{server.server_port}/backend-api/codex',
                          access_token=token, access_token_in_path=True).start()
    try:
        url = tap.local_base_url + '/responses'
        with httpx.Client(trust_env=False) as client:
            assert client.get(url, headers={'Upgrade': 'websocket', 'Connection': 'Upgrade'}).status_code == 426
            assert client.post(url.replace(token, 'wrong'), json={}).status_code == 403
            assert client.post(url, headers={'Origin': 'https://example.com'}, json={}).status_code == 403
            assert client.post(url, headers={'Host': 'example.com'}, json={}).status_code == 403
            response = client.post(url + '?test=1', headers={'Authorization': 'Bearer synthetic-chatgpt-token',
                                   'ChatGPT-Account-ID': 'synthetic-account'}, json={'input': 'hello'})
            assert response.status_code == 200
        assert len(received) == 1
        path, headers, body = received[0]
        assert path == '/backend-api/codex/responses?test=1'
        assert headers['Authorization'] == 'Bearer synthetic-chatgpt-token'
        assert headers['ChatGPT-Account-ID'] == 'synthetic-account'
        assert token not in path and token not in json.dumps(headers) and token.encode() not in body
        assert token not in json.dumps(tap.stats_dict())
    finally:
        tap.stop()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_parent_eof_restores_route_before_sidecar_exits(tmp_path):
    target = tmp_path / 'config.toml'
    original = 'model = "test"\n'
    target.write_text(original)
    process = subprocess.Popen([sys.executable, '-m', 'codexscope.desktop_companion', 'serve',
                                '--state-dir', str(tmp_path / 'state')],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, encoding='utf-8', env={**os.environ,
                               'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src')})
    try:
        assert json.loads(process.stdout.readline())['event'] == 'ready'
        process.stdin.write(json.dumps({'id': 1, 'method': 'connect', 'params': {
            'config_path': str(target), 'auth_kind': 'chatgpt', 'mode': 'off'}}) + '\n')
        process.stdin.flush()
        assert json.loads(process.stdout.readline())['result']['enabled']
        process.stdin.close()
        process.wait(timeout=15)
        assert process.returncode == 0
        assert target.read_text() == original
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
