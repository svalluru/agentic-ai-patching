#!/usr/bin/env python3
import argparse
import json
import logging
import os
import re
import shutil
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_LEGACY_DIR = Path(__file__).resolve().parent
WORKSPACE = Path(os.environ.get('WORKSPACE', str(_LEGACY_DIR.parent)))
STATE_FILE = WORKSPACE / 'cve_console' / 'state.json'
DOTENV_FILE = WORKSPACE / 'cve_console' / '.env'
RISK_URL = os.environ.get('RISK_URL', 'http://127.0.0.1:8080/v1/models/risk-score:predict')
LLAMA_URL = os.environ.get('LLAMA_STACK_URL', 'http://127.0.0.1:8321')
INSIGHTS_MCP_ENDPOINT = os.environ.get('INSIGHTS_MCP_ENDPOINT', 'http://localhost:8000/mcp')
INSIGHTS_TOOLGROUP = os.environ.get('INSIGHTS_TOOLGROUP', 'mcp::insights-sse')
GITHUB_MCP_ENDPOINT = os.environ.get('GITHUB_MCP_ENDPOINT', 'http://localhost:9800/sse')
GITHUB_REPO_OWNER = os.environ.get('GITHUB_REPO_OWNER', 'svalluru')
GITHUB_REPO_NAME = os.environ.get('GITHUB_REPO_NAME', 'agentic-ai-patching')
GITHUB_REPO_BRANCH = os.environ.get('GITHUB_REPO_BRANCH', 'main')
DEFAULT_CVE = 'CVE-2020-25681'
DEFAULT_PROJECT_ID = 43
DEFAULT_INVENTORY_ID = 1
DEFAULT_EXECUTION_ENVIRONMENT_ID = 2
DEFAULT_ORGANIZATION_ID = 1
DEFAULT_VECTOR_DB_ID = os.environ.get('VECTOR_DB_ID', 'vs_83ad9da7-beaf-49de-ba47-c19da320d7db')
DEFAULT_AAP_PROJECT_CHECKOUT = Path(os.environ.get('AAP_PROJECT_CHECKOUT', str(WORKSPACE / 'agentic-ai-patching')))
DEFAULT_LLM_MODEL = os.environ.get('DEFAULT_LLM_MODEL', 'vllm-inference/llama-scout-17b')

LOG = logging.getLogger('cve_flow')


def setup_logging() -> None:
    level_name = os.environ.get('CVE_FLOW_LOG_LEVEL', 'INFO').upper()
    level = getattr(logging, level_name, logging.INFO)
    if not LOG.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(
            logging.Formatter(
                '%(asctime)s [cve-flow] %(levelname)s %(message)s',
                datefmt='%Y-%m-%dT%H:%M:%S',
            )
        )
        LOG.addHandler(handler)
    LOG.setLevel(level)
    LOG.propagate = False


def log_step(step: str, **fields: Any) -> None:
    extra = ' '.join(f'{k}={v}' for k, v in fields.items() if v is not None)
    LOG.info('STEP %s%s', step, f' ({extra})' if extra else '')


def _summarize_kwargs(kwargs: dict[str, Any]) -> str:
    parts: list[str] = []
    for key, value in kwargs.items():
        text = json.dumps(value, default=str) if isinstance(value, (dict, list)) else str(value)
        if len(text) > 100:
            text = text[:97] + '...'
        parts.append(f'{key}={text}')
    return ', '.join(parts)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def get_ssl_context(verify_tls: bool):
    if verify_tls:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def http_json(url: str, method: str = 'GET', payload: Any = None, headers: dict[str, str] | None = None, verify_tls: bool = True):
    data = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=60, context=get_ssl_context(verify_tls)) as r:
            body = r.read().decode()
            return json.loads(body) if body else None
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        raise urllib.error.HTTPError(e.url, e.code, body or e.reason, e.headers, None) from e
    except ssl.SSLError as e:
        hint = ''
        if verify_tls and url.startswith('https://'):
            hint = ' Try setting AAP_VERIFY_TLS=false for sandbox/self-signed endpoints.'
        raise RuntimeError(f'SSL error calling {method} {url}: {e}.{hint}') from e
    except urllib.error.URLError as e:
        if isinstance(e.reason, ssl.SSLError):
            hint = ''
            if verify_tls and url.startswith('https://'):
                hint = ' Try setting AAP_VERIFY_TLS=false for sandbox/self-signed endpoints.'
            raise RuntimeError(f'SSL error calling {method} {url}: {e.reason}.{hint}') from e
        raise RuntimeError(f'Request failed {method} {url}: {e.reason}') from e


def parse_mcp_sse(body: str, *, allow_empty: bool = False) -> dict:
    for line in body.splitlines():
        line = line.strip()
        if line.startswith('data:'):
            payload = line[5:].lstrip()
            if payload:
                return json.loads(payload)
    body = body.strip()
    if body:
        return json.loads(body)
    if allow_empty:
        return {}
    raise RuntimeError('Empty MCP response')


def mcp_post(
    endpoint: str,
    payload: dict[str, Any],
    session_id: str | None = None,
    extra_headers: dict[str, str] | None = None,
    verify_tls: bool = True,
) -> tuple[str | None, dict]:
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json, text/event-stream',
    }
    if session_id:
        headers['Mcp-Session-Id'] = session_id
    if extra_headers:
        headers.update(extra_headers)
    data = json.dumps(payload).encode()
    req = urllib.request.Request(endpoint, data=data, method='POST', headers=headers)
    is_notification = 'id' not in payload
    with urllib.request.urlopen(req, timeout=120, context=get_ssl_context(verify_tls)) as r:
        new_session = r.headers.get('Mcp-Session-Id') or r.headers.get('mcp-session-id')
        raw = r.read().decode()
        if not raw.strip() and is_notification:
            LOG.debug('MCP notification accepted method=%s (empty body)', payload.get('method'))
            return new_session, {}
        return new_session, parse_mcp_sse(raw, allow_empty=is_notification)


class McpSession:
    """Streamable HTTP MCP client (RHOAI 0.7 — tool-runtime/invoke removed)."""

    def __init__(self, endpoint: str, extra_headers: dict[str, str] | None = None, verify_tls: bool = True):
        self.endpoint = endpoint
        self.extra_headers = extra_headers
        self.verify_tls = verify_tls
        self.session_id: str | None = None

    def ensure(self) -> None:
        if self.session_id:
            return
        session_id, msg = mcp_post(
            self.endpoint,
            {
                'jsonrpc': '2.0',
                'id': 1,
                'method': 'initialize',
                'params': {
                    'protocolVersion': '2024-11-05',
                    'capabilities': {},
                    'clientInfo': {'name': 'cve-console', 'version': '1.0'},
                },
            },
            extra_headers=self.extra_headers,
            verify_tls=self.verify_tls,
        )
        if msg.get('error'):
            raise RuntimeError(f'MCP initialize failed: {msg["error"]}')
        if not session_id:
            raise RuntimeError(f'MCP initialize did not return session id from {self.endpoint}')
        self.session_id = session_id
        LOG.info('MCP session opened endpoint=%s session_id=%s', self.endpoint, session_id[:8] + '...')
        mcp_post(
            self.endpoint,
            {'jsonrpc': '2.0', 'method': 'notifications/initialized', 'params': {}},
            session_id=self.session_id,
            extra_headers=self.extra_headers,
            verify_tls=self.verify_tls,
        )

    def list_tool_names(self) -> list[str]:
        self.ensure()
        _, msg = mcp_post(
            self.endpoint,
            {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list', 'params': {}},
            session_id=self.session_id,
            extra_headers=self.extra_headers,
            verify_tls=self.verify_tls,
        )
        if msg.get('error'):
            raise RuntimeError(f'MCP tools/list failed: {msg["error"]}')
        tools = (msg.get('result') or {}).get('tools') or []
        return [str(t.get('name')) for t in tools if t.get('name')]

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict:
        self.ensure()
        LOG.info(
            'MCP tools/call endpoint=%s tool=%s args={%s}',
            self.endpoint,
            tool_name,
            _summarize_kwargs(arguments),
        )
        started = time.monotonic()
        _, msg = mcp_post(
            self.endpoint,
            {
                'jsonrpc': '2.0',
                'id': 3,
                'method': 'tools/call',
                'params': {'name': tool_name, 'arguments': arguments},
            },
            session_id=self.session_id,
            extra_headers=self.extra_headers,
            verify_tls=self.verify_tls,
        )
        if msg.get('error'):
            LOG.error('MCP tools/call failed tool=%s error=%s', tool_name, msg['error'])
            raise RuntimeError(f'MCP tool {tool_name} failed: {msg["error"]}')
        result = msg.get('result') or {}
        content = result.get('content')
        full_text = parse_tool_text({'content': content}) if content else (result.get('text') or json.dumps(result))
        preview = full_text[:120].replace('\n', ' ')
        elapsed = time.monotonic() - started
        LOG.info(
            'MCP tools/call ok tool=%s elapsed=%.2fs response_chars=%d preview=%r',
            tool_name,
            elapsed,
            len(full_text),
            preview,
        )
        if content:
            return {'content': content}
        text = result.get('text') or json.dumps(result)
        return {'content': [{'type': 'text', 'text': text}]}


_insights_mcp: McpSession | None = None
_github_mcp: McpSession | None = None


def insights_mcp_session() -> McpSession:
    global _insights_mcp
    if _insights_mcp is None:
        extra = build_mcp_headers().get(INSIGHTS_MCP_ENDPOINT) or None
        _insights_mcp = McpSession(INSIGHTS_MCP_ENDPOINT, extra_headers=extra)
    return _insights_mcp


def github_mcp_session() -> McpSession:
    global _github_mcp
    if _github_mcp is None:
        extra: dict[str, str] = {}
        token = github_token()
        if token:
            extra['Authorization'] = f'Bearer {token}'
        _github_mcp = McpSession(GITHUB_MCP_ENDPOINT, extra_headers=extra or None)
    return _github_mcp


def is_insights_tool(tool_name: str) -> bool:
    return tool_name.startswith(('vulnerability__', 'remediations__', 'inventory__', 'advisor__'))


def is_github_mcp_tool(tool_name: str) -> bool:
    return tool_name.endswith(('push_files', 'create_or_update_file')) or tool_name.startswith('github__')


def parse_tool_text(result: dict) -> str:
    parts = []
    for item in result.get('content', []) or []:
        text = item.get('text')
        if text:
            parts.append(text)
    return '\n'.join(parts).strip()


_tools_indexed = False
_github_push_tool_name: str | None = None


def github_token() -> str:
    return (os.environ.get('GIT_HUB_TOKEN') or os.environ.get('GITHUB_TOKEN') or '').strip()


def github_repo_branch() -> str:
    return os.environ.get('GITHUB_REPO_BRANCH', GITHUB_REPO_BRANCH).strip() or 'main'


def git_identity_env() -> dict[str, str]:
    name = os.environ.get('GIT_USER_NAME', 'cve-console').strip() or 'cve-console'
    email = os.environ.get('GIT_USER_EMAIL', 'cve-console@agentic-patching.local').strip() or 'cve-console@agentic-patching.local'
    return {
        'GIT_AUTHOR_NAME': name,
        'GIT_AUTHOR_EMAIL': email,
        'GIT_COMMITTER_NAME': name,
        'GIT_COMMITTER_EMAIL': email,
    }


def git_env(repo_root: Path | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env.update(git_identity_env())
    env['GIT_TERMINAL_PROMPT'] = '0'
    if os.environ.get('GITHUB_VERIFY_TLS', 'true').lower() in {'0', 'false', 'no'}:
        env['GIT_SSL_NO_VERIFY'] = 'true'
    return env


def ensure_git_repo_identity(repo_root: Path) -> None:
    """Set repo-local identity so git commit works in containers without global config."""
    name = git_identity_env()['GIT_AUTHOR_NAME']
    email = git_identity_env()['GIT_AUTHOR_EMAIL']
    env = git_env(repo_root)
    for key, value in (('user.name', name), ('user.email', email)):
        subprocess.run(
            ['git', '-C', str(repo_root), 'config', '--local', key, value],
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )
    subprocess.run(
        ['git', '-C', str(repo_root), 'config', '--local', 'safe.directory', str(repo_root.resolve())],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def aap_git_repo_url() -> str:
    owner = os.environ.get('GITHUB_REPO_OWNER', GITHUB_REPO_OWNER).strip()
    repo = os.environ.get('GITHUB_REPO_NAME', GITHUB_REPO_NAME).strip()
    return os.environ.get('AAP_GIT_REPO_URL', f'https://github.com/{owner}/{repo}.git').strip()


def clone_aap_git_repo(repo_root: Path, *, preserve_paths: list[str] | None = None) -> None:
    branch = github_repo_branch()
    url = aap_git_repo_url()
    token = github_token()
    clone_url = _github_auth_remote_url(url, token) if token else url
    preserved: dict[str, str] = {}
    if preserve_paths and repo_root.exists():
        for rel in preserve_paths:
            path = repo_root / rel
            if path.is_file():
                preserved[rel] = path.read_text()
    if repo_root.exists():
        shutil.rmtree(repo_root)
    repo_root.parent.mkdir(parents=True, exist_ok=True)
    env = git_env()
    clone = subprocess.run(
        ['git', 'clone', '--depth', '1', '--branch', branch, clone_url, str(repo_root)],
        check=False,
        env=env,
        capture_output=True,
        text=True,
    )
    if clone.returncode != 0:
        raise RuntimeError(f'git clone failed for {url}: {clone.stderr or clone.stdout}')
    ensure_git_repo_identity(repo_root)
    for rel, content in preserved.items():
        dest = repo_root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content)
    LOG.info('git clone ok repo=%s branch=%s', repo_root, branch)


def ensure_git_checkout_ready(repo_root: Path, *, preserve_paths: list[str] | None = None) -> str:
    """Ensure AAP repo has a valid branch HEAD (fixes broken shallow clones on PVC)."""
    branch = github_repo_branch()
    if not (repo_root / '.git').exists():
        LOG.info('AAP git checkout missing; cloning into %s', repo_root)
        clone_aap_git_repo(repo_root, preserve_paths=preserve_paths)
        return branch

    env = git_env(repo_root)
    ensure_git_repo_identity(repo_root)
    head_ok = subprocess.run(
        ['git', '-C', str(repo_root), 'rev-parse', '--verify', 'HEAD'],
        check=False,
        env=env,
        capture_output=True,
    ).returncode == 0

    if not head_ok:
        LOG.warning('git HEAD invalid at %s; re-cloning', repo_root)
        clone_aap_git_repo(repo_root, preserve_paths=preserve_paths)
        return branch

    origin = subprocess.run(
        ['git', '-C', str(repo_root), 'remote', 'get-url', 'origin'],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    ).stdout.strip()
    token = github_token()
    auth_origin = _github_auth_remote_url(origin, token) if token and origin else origin
    if auth_origin and origin and auth_origin != origin:
        subprocess.run(['git', '-C', str(repo_root), 'remote', 'set-url', 'origin', auth_origin], check=False, env=env)
    fetch = subprocess.run(
        ['git', '-C', str(repo_root), 'fetch', 'origin', branch, '--depth', '1'],
        check=False,
        env=env,
        capture_output=True,
        text=True,
    )
    if auth_origin and origin and auth_origin != origin:
        subprocess.run(['git', '-C', str(repo_root), 'remote', 'set-url', 'origin', origin], check=False, env=env)
    if fetch.returncode != 0:
        LOG.warning('git fetch failed; re-cloning: %s', fetch.stderr or fetch.stdout)
        clone_aap_git_repo(repo_root, preserve_paths=preserve_paths)
        return branch

    reset = subprocess.run(
        ['git', '-C', str(repo_root), 'reset', '--hard', f'origin/{branch}'],
        check=False,
        env=env,
        capture_output=True,
        text=True,
    )
    if reset.returncode != 0:
        checkout = subprocess.run(
            ['git', '-C', str(repo_root), 'checkout', '-B', branch, f'origin/{branch}'],
            check=False,
            env=env,
            capture_output=True,
            text=True,
        )
        if checkout.returncode != 0:
            LOG.warning('git checkout repair failed; re-cloning: %s', checkout.stderr or checkout.stdout)
            clone_aap_git_repo(repo_root, preserve_paths=preserve_paths)
    return branch


def _git_commit(repo_root: Path, repo_relative_path: str, cve_id: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    subprocess.run(['git', '-C', str(repo_root), 'add', repo_relative_path], check=True, env=env)
    return subprocess.run(
        ['git', '-C', str(repo_root), 'commit', '-m', f'Add v3 remediation playbook for {cve_id}'],
        check=False,
        env=env,
        capture_output=True,
        text=True,
    )


def playbook_push_method() -> str:
    return os.environ.get('PLAYBOOK_PUSH_METHOD', 'git').strip().lower()


def build_mcp_headers() -> dict[str, dict[str, str]]:
    mcp_headers: dict[str, dict[str, str]] = {}
    client_id = os.environ.get('LIGHTSPEED_CLIENT_ID', '').strip()
    client_secret = os.environ.get('LIGHTSPEED_CLIENT_SECRET', '').strip()
    if client_id and client_secret:
        mcp_headers[INSIGHTS_MCP_ENDPOINT] = {
            'lightspeed-client-id': client_id,
            'lightspeed-client-secret': client_secret,
        }
    token = github_token()
    if token:
        github_endpoint = os.environ.get('GITHUB_MCP_ENDPOINT', GITHUB_MCP_ENDPOINT)
        mcp_headers[github_endpoint] = {'Authorization': f'Bearer {token}'}
    return mcp_headers


def llama_request_headers() -> dict[str, str]:
    headers = {'Content-Type': 'application/json'}
    mcp_headers = build_mcp_headers()
    if mcp_headers:
        headers['X-LlamaStack-Provider-Data'] = json.dumps({'mcp_headers': mcp_headers})
    return headers


def ensure_tools_indexed() -> None:
    """No-op on RHOAI 0.7 (tool-runtime/list-tools removed). Kept for API compatibility."""
    global _tools_indexed
    _tools_indexed = True


def invoke_tool(tool_name: str, kwargs: dict[str, Any]) -> dict:
    if is_insights_tool(tool_name):
        LOG.debug('invoke_tool route=insights-mcp tool=%s', tool_name)
        return insights_mcp_session().call_tool(tool_name, kwargs)
    if is_github_mcp_tool(tool_name):
        LOG.debug('invoke_tool route=github-mcp tool=%s', tool_name)
        return github_mcp_session().call_tool(tool_name, kwargs)
    LOG.debug('invoke_tool route=llama-tool-runtime tool=%s', tool_name)
    ensure_tools_indexed()
    try:
        return http_json(
            f'{LLAMA_URL}/v1/tool-runtime/invoke',
            method='POST',
            payload={'tool_name': tool_name, 'kwargs': kwargs},
            headers=llama_request_headers(),
            verify_tls=True,
        )
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise RuntimeError(
                f'Tool {tool_name} is not available: Llama Stack tool-runtime/invoke removed in 0.7. '
                'Use direct MCP (Insights/GitHub) or set PLAYBOOK_PUSH_METHOD=git.'
            ) from e
        raise


def llm_summarize_host_rag(host: str, rag_text: str) -> str:
    LOG.info('LLM summarize host=%s model=%s input_chars=%d', host, DEFAULT_LLM_MODEL, len(rag_text))
    prompt = (
        f'Summarize the following retrieved host history for {host} in 2-4 concise sentences. '
        'Focus only on operationally useful review context: repeated failures, approval friction, manual intervention, '\
        'and remediation risk. Do not mention chunk counts, retrieval mechanics, or raw metadata unless directly useful.\n\n'
        f'{rag_text[:6000]}'
    )
    result = http_json(
        f'{LLAMA_URL}/v1/responses',
        method='POST',
        payload={
            'model': DEFAULT_LLM_MODEL,
            'input': [{'role': 'user', 'content': prompt}],
            'stream': False,
        },
        headers={'Content-Type': 'application/json'},
        verify_tls=True,
    )
    output = result.get('output', []) or []
    for item in output:
        for content in item.get('content', []) or []:
            text = content.get('text')
            if text and text.strip():
                LOG.info('LLM summarize ok host=%s output_chars=%d', host, len(text.strip()))
                return text.strip()
    raise RuntimeError(f'LLM summarization returned no text: {result}')


def risk_score(cvss: float, age_days: int, affected_hosts: int, finding_type: str = 'security') -> float:
    payload = {'instances': [{'cvss': cvss, 'age_days': age_days, 'affected_hosts': affected_hosts, 'type': finding_type}]}
    try:
        result = http_json(RISK_URL, method='POST', payload=payload, headers={'Content-Type': 'application/json'}, verify_tls=True)
        for key in ('predictions', 'outputs', 'data'):
            if key in result and result[key]:
                value = result[key][0]
                if isinstance(value, dict):
                    for inner in ('score', 'risk_score', 'prediction', 'value'):
                        if inner in value:
                            return float(value[inner])
                return float(value)
        raise RuntimeError(f'Unexpected risk model response: {result}')
    except Exception:
        # Fallback heuristic so the end-to-end flow still works when the local risk endpoint is down.
        return round((cvss * 6.0) + min(age_days / 30.0, 10.0) + min(affected_hosts, 10), 2)


def age_days_from_timestamp(first_reported: str | None) -> int:
    if not first_reported:
        return 90
    try:
        first = datetime.fromisoformat(first_reported.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        return max(1, (now - first).days)
    except Exception:
        return 90


@dataclass
class HostRisk:
    host: str
    system_uuid: str | None
    age_days: int
    risk_score: float
    decision: str
    reason: str
    decision_support: dict[str, Any] | None = None


def extract_json_text(tool_result: dict) -> Any:
    text = parse_tool_text(tool_result)
    if '[INSTRUCTION]' in text and 'No credentials found in request headers' in text:
        raise RuntimeError(
            'Insights MCP authentication failed. Create a Red Hat service account at '
            'https://console.redhat.com/iam/service-accounts and set LIGHTSPEED_CLIENT_ID '
            'and LIGHTSPEED_CLIENT_SECRET in cve_console/.env, then restart the console.'
        )
    candidates = [text]
    start_obj, end_obj = text.find('{'), text.rfind('}')
    if start_obj != -1 and end_obj != -1 and end_obj >= start_obj:
        candidates.append(text[start_obj:end_obj + 1])
    start_arr, end_arr = text.find('['), text.rfind(']')
    if start_arr != -1 and end_arr != -1 and end_arr >= start_arr:
        candidates.append(text[start_arr:end_arr + 1])
    for candidate in candidates:
        try:
            return json.loads(candidate)
        except Exception:
            continue
    raise RuntimeError(f'Could not parse tool JSON from: {text[:500]}')


def fetch_cve_and_systems(cve_id: str) -> tuple[dict, list[dict]]:
    log_step('fetch_cve_and_systems', cve=cve_id, endpoint=INSIGHTS_MCP_ENDPOINT)
    cve_result = invoke_tool('vulnerability__get_cve', {'cve': cve_id})
    systems_result = invoke_tool('vulnerability__get_cve_systems', {'cve': cve_id, 'limit': 100, 'offset': 0})
    cve_data = extract_json_text(cve_result)
    systems_data = extract_json_text(systems_result)
    systems = systems_data.get('data', []) if isinstance(systems_data, dict) else systems_data
    LOG.info('fetch_cve_and_systems done cve=%s affected_systems=%d', cve_id, len(systems))
    return cve_data, systems


def generate_playbook(cve_id: str, uuids: list[str]) -> str:
    log_step('generate_playbook', cve=cve_id, review_hosts=len(uuids))
    result = invoke_tool('remediations__create_vuln_playbook', {
        'playbook_name': f'{cve_id}-v3-remediation.yml',
        'cves': [cve_id],
        'uuids': uuids,
    })
    text = parse_tool_text(result)
    if '---' in text:
        text = text[text.find('---'):]
    if not text.strip().startswith('---'):
        raise RuntimeError(f'Remediation output did not look like YAML: {text[:500]}')
    LOG.info('generate_playbook done cve=%s yaml_bytes=%d', cve_id, len(text))
    return text.strip() + '\n'


def search_vector_store(vector_store_id: str, query: str, max_results: int = 5) -> dict[str, Any]:
    """RHOAI 0.7: RAG via OpenAI-compatible vector store search (not tool-runtime/knowledge_search)."""
    LOG.info(
        'vector_store search store=%s max_results=%d query=%r',
        vector_store_id,
        max_results,
        query[:120],
    )
    url = f'{LLAMA_URL}/v1/vector_stores/{vector_store_id}/search'
    headers = {'Content-Type': 'application/json'}
    for payload in (
        {'query': query, 'max_num_results': max_results},
        {'query': query, 'max_results': max_results},
    ):
        try:
            result = http_json(url, method='POST', payload=payload, headers=headers, verify_tls=True)
            hits = len((result or {}).get('data') or [])
            LOG.info('vector_store search ok store=%s hits=%d', vector_store_id, hits)
            return result
        except Exception:
            continue
    raise RuntimeError(f'Vector store search failed for {vector_store_id}')


def format_vector_search_results(result: dict[str, Any]) -> str:
    items = result.get('data', []) or []
    parts = [f'vector_store search found {len(items)} chunks:', 'BEGIN of vector store search results.', '']
    for i, item in enumerate(items, start=1):
        content_parts = []
        for chunk in item.get('content', []) or []:
            if isinstance(chunk, dict) and chunk.get('text'):
                content_parts.append(chunk['text'])
        attrs = item.get('attributes') or item.get('metadata') or {}
        parts.append(f'Result {i}')
        parts.append(f'Content: {" ".join(content_parts)}')
        parts.append(f'Metadata: {attrs}')
        parts.append('')
    return '\n'.join(parts).strip()


def rag_summary_for_host(host: str, vector_db_id: str) -> dict[str, Any]:
    log_step('rag_summary_for_host', host=host, vector_db=vector_db_id)
    query = (
        f'For host {host}, summarize past issues, previous performance, remediation problems, '
        'and useful review context.'
    )
    search_result = search_vector_store(vector_db_id, query, max_results=5)
    text = format_vector_search_results(search_result)
    matches = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('display_name:'):
            matches.append(line.split(':', 1)[1].strip())
        elif line.startswith('status_name:') or line.startswith('status_text:'):
            matches.append(line)
        elif 'display_name' in line and ':' in line:
            matches.append(line.split(':', 1)[1].strip())
    summary = llm_summarize_host_rag(host, text)
    LOG.info('rag_summary_for_host done host=%s summary_chars=%d', host, len(summary))
    return {
        'summary': summary,
        'vector_db_id': vector_db_id,
        'matches': matches[:10],
        'raw': text[:4000],
    }


def aap_headers() -> tuple[str, dict[str, str], bool]:
    token = os.environ.get('AAP_TOKEN') or os.environ.get('CONTROLLER_OAUTH_TOKEN') or os.environ.get('AWX_TOKEN')
    base = os.environ.get('AAP_BASE_URL') or os.environ.get('AAP_URL') or os.environ.get('CONTROLLER_HOST') or os.environ.get('AWX_HOST')
    if not token or not base:
        raise RuntimeError('AAP credentials not configured in cve_console/.env')
    if '/api/controller/' in base:
        base = base.split('/api/controller/')[0]
    base = base.rstrip('/')
    verify_tls = os.environ.get('AAP_VERIFY_TLS', 'false').lower() in {'1', 'true', 'yes'}
    return base, {'Authorization': f'Bearer {token}', 'Accept': 'application/json', 'Content-Type': 'application/json'}, verify_tls


def aap_req(path: str, method: str = 'GET', payload: Any = None, **params):
    base, headers, verify_tls = aap_headers()
    url = base + path
    if params:
        url += '?' + urllib.parse.urlencode(params)
    LOG.info('AAP request %s %s verify_tls=%s', method, url, verify_tls)
    return http_json(url, method=method, payload=payload, headers=headers, verify_tls=verify_tls)


def wait_for_project_update(project_update_id: int, timeout_seconds: int = 180) -> dict[str, Any]:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        update = aap_req(f'/api/controller/v2/project_updates/{project_update_id}/')
        status = update.get('status')
        if status in {'successful', 'failed', 'error', 'canceled'}:
            return update
        time.sleep(2)
    return aap_req(f'/api/controller/v2/project_updates/{project_update_id}/')


def sync_project(project_id: int = DEFAULT_PROJECT_ID) -> dict[str, Any]:
    log_step('sync_project', project_id=project_id)
    launch = aap_req(f'/api/controller/v2/projects/{project_id}/update/', method='POST', payload={})
    update_id = launch.get('project_update') or launch.get('id')
    if not update_id:
        raise RuntimeError(f'Could not determine project update id from launch payload: {launch}')
    update = wait_for_project_update(update_id)
    if update.get('status') != 'successful':
        raise RuntimeError(f'Project sync failed: {update}')
    LOG.info('sync_project done project_id=%s status=%s', project_id, update.get('status'))
    return update


def _github_auth_remote_url(origin: str, token: str) -> str:
    match = re.search(r'github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/.]+)(?:\.git)?', origin)
    if not match:
        raise RuntimeError(f'Cannot parse GitHub origin URL: {origin}')
    return f"https://x-access-token:{token}@github.com/{match.group('owner')}/{match.group('repo')}.git"


def _parse_github_repo_from_origin(origin: str) -> tuple[str, str]:
    match = re.search(r'github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/.]+)(?:\.git)?', origin)
    if not match:
        raise RuntimeError(f'Cannot parse GitHub origin URL: {origin}')
    return match.group('owner'), match.group('repo')


def _github_repo_target(repo_root: Path) -> tuple[str, str, str]:
    owner = os.environ.get('GITHUB_REPO_OWNER', GITHUB_REPO_OWNER).strip()
    repo = os.environ.get('GITHUB_REPO_NAME', GITHUB_REPO_NAME).strip()
    branch = os.environ.get('GITHUB_REPO_BRANCH', GITHUB_REPO_BRANCH).strip()
    if repo_root.exists():
        origin = subprocess.run(
            ['git', '-C', str(repo_root), 'remote', 'get-url', 'origin'],
            check=False,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if origin:
            owner, repo = _parse_github_repo_from_origin(origin)
    return owner, repo, branch


def _tool_names_from_listing(listing: Any) -> list[str]:
    if isinstance(listing, list):
        tools = listing
    elif isinstance(listing, dict):
        tools = listing.get('data') or listing.get('tools') or listing.get('results') or []
    else:
        tools = []
    names: list[str] = []
    for tool in tools:
        if isinstance(tool, str):
            names.append(tool)
            continue
        if not isinstance(tool, dict):
            continue
        name = tool.get('identifier') or tool.get('name') or tool.get('tool_name')
        if name:
            names.append(str(name))
    return names


def resolve_github_push_tool_name() -> str:
    global _github_push_tool_name
    if _github_push_tool_name:
        return _github_push_tool_name
    override = os.environ.get('GITHUB_MCP_PUSH_TOOL', '').strip()
    if override:
        _github_push_tool_name = override
        return override
    try:
        names = github_mcp_session().list_tool_names()
    except Exception:
        names = []
    for candidate_suffix in ('push_files', 'create_or_update_file'):
        for name in names:
            if name == candidate_suffix or name.endswith(f'__{candidate_suffix}'):
                _github_push_tool_name = name
                return name
    for candidate_suffix in ('push_files', 'create_or_update_file'):
        _github_push_tool_name = candidate_suffix
        return candidate_suffix
    raise RuntimeError(
        'GitHub MCP push tool not found (expected push_files or create_or_update_file). '
        f'Sample registered tools: {names[:25]}'
    )


def mcp_push_playbook(
    repo_root: Path,
    repo_relative_path: str,
    cve_id: str,
    playbook_yaml: str,
) -> None:
    if not github_token():
        raise RuntimeError('PLAYBOOK_PUSH_METHOD=mcp requires GIT_HUB_TOKEN or GITHUB_TOKEN in cve_console/.env')
    owner, repo, branch = _github_repo_target(repo_root)
    tool_name = resolve_github_push_tool_name()
    message = f'Add v3 remediation playbook for {cve_id}'
    if tool_name.endswith('create_or_update_file') or tool_name == 'create_or_update_file':
        kwargs = {
            'owner': owner,
            'repo': repo,
            'branch': branch,
            'path': repo_relative_path,
            'message': message,
            'content': playbook_yaml,
        }
    else:
        kwargs = {
            'owner': owner,
            'repo': repo,
            'branch': branch,
            'message': message,
            'files': [{'path': repo_relative_path, 'content': playbook_yaml}],
        }
    result = invoke_tool(tool_name, kwargs)
    if result.get('error_code'):
        raise RuntimeError(f'GitHub MCP push failed via {tool_name}: {parse_tool_text(result)[:500]}')
    sync_local_repo_after_mcp_push(repo_root, branch)


def sync_local_repo_after_mcp_push(repo_root: Path, branch: str) -> None:
    if not repo_root.exists():
        return
    token = github_token()
    push_env = os.environ.copy()
    push_env['GIT_TERMINAL_PROMPT'] = '0'
    origin = subprocess.run(
        ['git', '-C', str(repo_root), 'remote', 'get-url', 'origin'],
        check=False,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if token and origin:
        auth_origin = _github_auth_remote_url(origin, token)
        subprocess.run(['git', '-C', str(repo_root), 'remote', 'set-url', 'origin', auth_origin], check=True)
        try:
            subprocess.run(['git', '-C', str(repo_root), 'pull', '--rebase', 'origin', branch], check=False, env=push_env)
        finally:
            subprocess.run(['git', '-C', str(repo_root), 'remote', 'set-url', 'origin', origin], check=False)
    else:
        subprocess.run(['git', '-C', str(repo_root), 'pull', '--rebase', 'origin', branch], check=False, env=push_env)


def publish_playbook(
    repo_root: Path,
    repo_relative_path: str,
    cve_id: str,
    playbook_yaml: str,
) -> str:
    method = playbook_push_method()
    log_step('publish_playbook', cve=cve_id, method=method, path=repo_relative_path)
    if method == 'mcp':
        mcp_push_playbook(repo_root, repo_relative_path, cve_id, playbook_yaml)
        return 'mcp'
    if method != 'git':
        raise RuntimeError(f'Unsupported PLAYBOOK_PUSH_METHOD={method!r}; use "git" or "mcp"')
    git_commit_and_push_playbook(repo_root, repo_relative_path, cve_id)
    LOG.info('publish_playbook done cve=%s method=git', cve_id)
    return 'git'


def git_commit_and_push_playbook(repo_root: Path, repo_relative_path: str, cve_id: str) -> None:
    branch = ensure_git_checkout_ready(repo_root, preserve_paths=[repo_relative_path])
    env = git_env(repo_root)
    commit = _git_commit(repo_root, repo_relative_path, cve_id, env)
    commit_output = (commit.stdout + commit.stderr).lower()
    if commit.returncode not in (0, 1):
        if 'unable to resolve head' in commit_output:
            LOG.warning('git commit HEAD error; re-cloning and retrying')
            clone_aap_git_repo(repo_root, preserve_paths=[repo_relative_path])
            ensure_git_repo_identity(repo_root)
            commit = _git_commit(repo_root, repo_relative_path, cve_id, git_env(repo_root))
            commit_output = (commit.stdout + commit.stderr).lower()
        if commit.returncode not in (0, 1):
            raise RuntimeError(f'git commit failed: {commit.stderr or commit.stdout}')
    if commit.returncode == 1 and 'nothing to commit' not in commit_output:
        raise RuntimeError(f'git commit failed: {commit.stderr or commit.stdout}')
    if commit.returncode == 0:
        LOG.info('git commit ok repo=%s path=%s', repo_root, repo_relative_path)
    else:
        LOG.info('git commit skipped (no changes) repo=%s path=%s', repo_root, repo_relative_path)

    origin = subprocess.run(
        ['git', '-C', str(repo_root), 'remote', 'get-url', 'origin'],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout.strip()
    token = github_token()
    if not token:
        raise RuntimeError('GIT_HUB_TOKEN (or GITHUB_TOKEN) is required for git playbook push')
    auth_origin = _github_auth_remote_url(origin, token)
    subprocess.run(['git', '-C', str(repo_root), 'remote', 'set-url', 'origin', auth_origin], check=True, env=env)
    try:
        push = subprocess.run(
            ['git', '-C', str(repo_root), 'push', 'origin', branch],
            check=False,
            env=env,
            capture_output=True,
            text=True,
        )
        if push.returncode != 0:
            raise RuntimeError(f'git push origin {branch} failed: {push.stderr or push.stdout}')
        LOG.info('git push ok repo=%s branch=%s', repo_root, branch)
    finally:
        subprocess.run(['git', '-C', str(repo_root), 'remote', 'set-url', 'origin', origin], check=False, env=env)


def create_templates(cve_id: str, playbook_path: str) -> dict[str, Any]:
    log_step('create_templates', cve=cve_id, playbook=playbook_path)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    jt = aap_req('/api/controller/v2/job_templates/', method='POST', payload={
        'name': f'ai patching cve remediation v3 {stamp}',
        'job_type': 'run',
        'inventory': DEFAULT_INVENTORY_ID,
        'project': DEFAULT_PROJECT_ID,
        'playbook': playbook_path,
        'ask_variables_on_launch': True,
        'execution_environment': DEFAULT_EXECUTION_ENVIRONMENT_ID,
    })
    wf = aap_req('/api/controller/v2/workflow_job_templates/', method='POST', payload={
        'name': f'ai patching approval workflow v3 {stamp}',
        'organization': DEFAULT_ORGANIZATION_ID,
        'inventory': DEFAULT_INVENTORY_ID,
        'ask_variables_on_launch': True,
        'extra_vars': json.dumps({'cve_id': cve_id, 'playbook_path': playbook_path, 'mode': 'hybrid-v3'}),
    })
    wf_id = wf['id']
    jt_id = jt['id']
    approval = aap_req(f'/api/controller/v2/workflow_job_templates/{wf_id}/workflow_nodes/', method='POST', payload={
        'identifier': 'approval_review',
        'all_parents_must_converge': False,
    })
    approval_id = approval['id']
    aap_req(f'/api/controller/v2/workflow_job_template_nodes/{approval_id}/create_approval_template/', method='POST', payload={
        'name': 'approval_review',
        'description': f'Manual approval required before remediation for {cve_id}',
        'timeout': 86400,
    })
    run_node = aap_req(f'/api/controller/v2/workflow_job_templates/{wf_id}/workflow_nodes/', method='POST', payload={
        'identifier': 'run_remediation',
        'unified_job_template': jt_id,
        'all_parents_must_converge': False,
    })
    run_node_id = run_node['id']
    aap_req(f'/api/controller/v2/workflow_job_template_nodes/{approval_id}/success_nodes/', method='POST', payload={'id': run_node_id})
    nodes = aap_req(f'/api/controller/v2/workflow_job_templates/{wf_id}/workflow_nodes/')
    results = nodes.get('results', []) if isinstance(nodes, dict) else []
    has_approval = False
    for node in results:
        if node.get('identifier') != 'approval_review':
            continue
        related = node.get('related', {}) or {}
        if related.get('create_approval_template'):
            has_approval = True
        if node.get('unified_job_template') is None and node.get('success_nodes'):
            has_approval = True
    if not has_approval:
        raise RuntimeError(f'Approval gate verification failed for workflow template {wf_id}')
    base, _, _ = aap_headers()
    LOG.info(
        'create_templates done cve=%s job_template_id=%s workflow_template_id=%s',
        cve_id,
        jt_id,
        wf_id,
    )
    return {
        'job_template_id': jt_id,
        'workflow_template_id': wf_id,
        'job_template_ui_url': f'{base}/#/templates/job_template/{jt_id}/details',
        'workflow_template_ui_url': f'{base}/#/templates/workflow_job_template/{wf_id}/details',
    }


def launch_workflow_template(workflow_template_id: int) -> dict[str, Any]:
    log_step('launch_workflow_template', workflow_template_id=workflow_template_id)
    result = aap_req(f'/api/controller/v2/workflow_job_templates/{workflow_template_id}/launch/', method='POST', payload={})
    LOG.info('launch_workflow_template done workflow_template_id=%s job_id=%s', workflow_template_id, result.get('id'))
    return result


def poll_latest_status(workflow_template_id: int, job_template_id: int) -> dict[str, Any]:
    log_step('poll_latest_status', workflow_template_id=workflow_template_id, job_template_id=job_template_id)
    base, _, _ = aap_headers()
    wf_runs = aap_req('/api/controller/v2/workflow_jobs/', workflow_job_template=workflow_template_id, order_by='-id', page_size=1)
    job_runs = aap_req('/api/controller/v2/jobs/', job_template=job_template_id, order_by='-id', page_size=1)
    latest_wf = (wf_runs.get('results') or [None])[0]
    latest_job = (job_runs.get('results') or [None])[0]
    wf_status = latest_wf.get('status') if latest_wf else None
    job_status = latest_job.get('status') if latest_job else None
    LOG.info(
        'poll_latest_status done workflow_status=%s job_status=%s',
        wf_status,
        job_status,
    )
    return {
        'latest_workflow_job': None if not latest_wf else {
            'id': latest_wf.get('id'), 'name': latest_wf.get('name'), 'status': latest_wf.get('status'), 'started': latest_wf.get('started'), 'finished': latest_wf.get('finished'), 'url': f"{base}{latest_wf.get('url')}" if latest_wf.get('url') else None,
        },
        'latest_job': None if not latest_job else {
            'id': latest_job.get('id'), 'name': latest_job.get('name'), 'status': latest_job.get('status'), 'started': latest_job.get('started'), 'finished': latest_job.get('finished'), 'url': f"{base}{latest_job.get('url')}" if latest_job.get('url') else None,
        }
    }


def update_state(
    cve_id: str,
    cve_summary: str,
    playbook_path: str,
    hosts: list[HostRisk],
    templates: dict[str, Any],
    status: dict[str, Any],
    push_method: str = 'git',
) -> None:
    state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    triggered_at = now_iso()
    state['workflow'] = {
        'name': f'{cve_id} remediation workflow',
        'cve': cve_id,
        'status': status['latest_workflow_job']['status'] if status.get('latest_workflow_job') else 'review_pending',
        'last_updated': triggered_at,
        'polling': 'live',
        'triggered_at': triggered_at,
    }
    state['summary'] = {
        'mode': 'hybrid-v3',
        'job_template_url': templates['job_template_ui_url'],
        'workflow_template_url': templates['workflow_template_ui_url'],
        'playbook_path': playbook_path,
        'playbook_push_method': push_method,
        'review_reason': 'Risk threshold exceeded (>30) for one or more affected hosts.',
        'approval_state': 'pending_review' if not status.get('latest_workflow_job') else status['latest_workflow_job']['status'],
        'last_job_status': status['latest_job']['status'] if status.get('latest_job') else 'unknown',
        'last_workflow_status': status['latest_workflow_job']['status'] if status.get('latest_workflow_job') else 'not_started',
        'cve_summary': cve_summary,
        'vector_store_id': DEFAULT_VECTOR_DB_ID,
    }
    state['hosts'] = [asdict(h) for h in hosts]
    base, _, _ = aap_headers()
    state['aap'] = {
        'enabled': True,
        'base_url': base,
        'workflow_template_id': templates['workflow_template_id'],
        'job_template_id': templates['job_template_id'],
        'workflow_jobs_endpoint': f"{base}/api/controller/v2/workflow_jobs/?workflow_job_template={templates['workflow_template_id']}&order_by=-id&page_size=1",
        'job_launch_endpoint': f"{base}/api/controller/v2/job_templates/{templates['job_template_id']}/launch/",
        'last_poll': triggered_at,
        'last_error': None,
        'latest_workflow_job': status.get('latest_workflow_job'),
        'latest_job': status.get('latest_job'),
    }
    run_entry = {
        'triggered_at': triggered_at,
        'workflow': state['workflow'],
        'summary': state['summary'],
        'hosts': state['hosts'],
        'aap': state['aap'],
    }
    runs = state.get('runs', [])
    runs.insert(0, run_entry)
    state['runs'] = runs[:50]
    state['stream'] = [
        {'time': triggered_at, 'event': 'cve_loaded', 'message': f'{cve_id} details loaded from Insights.'},
        {'time': triggered_at, 'event': 'playbook_generated', 'message': f'Generated v3 remediation playbook at {playbook_path}.'},
        {
            'time': triggered_at,
            'event': 'playbook_pushed',
            'message': f'Published playbook via {push_method} to GitHub ({playbook_path}).',
        },
        {'time': triggered_at, 'event': 'workflow_template_created', 'message': f"Created workflow template {templates['workflow_template_id']}."},
        {'time': triggered_at, 'event': 'workflow_launched', 'message': f"Launched workflow template {templates['workflow_template_id']}."},
    ]
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


def main() -> int:
    parser = argparse.ArgumentParser(description='Run the CVE v3 end-to-end patch flow')
    parser.add_argument('--cve', default=DEFAULT_CVE, help='CVE ID to process')
    args = parser.parse_args()

    setup_logging()
    load_dotenv(DOTENV_FILE)
    cve_id = args.cve
    log_step(
        'workflow_start',
        cve=cve_id,
        insights_mcp=INSIGHTS_MCP_ENDPOINT,
        llama_stack=LLAMA_URL,
        vector_db=DEFAULT_VECTOR_DB_ID,
    )

    try:
        cve_data, systems = fetch_cve_and_systems(cve_id)
        attrs = cve_data['data']['attributes']
        cve_summary = attrs.get('description', '')
        cvss = float(attrs.get('cvss3_score') or attrs.get('cvss2_score') or 0.0)
        affected_count = int(attrs.get('affected_systems') or len(systems))
        LOG.info('CVE loaded cve=%s cvss=%.1f affected_count=%d systems_returned=%d', cve_id, cvss, affected_count, len(systems))

        host_risks = []
        for sys_item in systems:
            sattrs = sys_item.get('attributes', {})
            host_name = sattrs.get('display_name') or sys_item.get('id') or 'unknown-host'
            uuid = sys_item.get('id') or sattrs.get('id') or sattrs.get('inventory_id')
            age_days = age_days_from_timestamp(sattrs.get('first_reported'))
            score = round(risk_score(cvss, age_days, affected_count, 'security'), 2)
            decision = 'review' if score > 30 else 'ok'
            reason = 'Kernel package update requires explicit approval.' if decision == 'review' else 'Below risk threshold.'
            if decision == 'review':
                log_step('host_risk_review', host=host_name, score=score)
                decision_support = rag_summary_for_host(host_name, DEFAULT_VECTOR_DB_ID)
            else:
                decision_support = None
            host_risks.append(HostRisk(host=host_name, system_uuid=uuid, age_days=age_days, risk_score=score, decision=decision, reason=reason, decision_support=decision_support))

        review_uuids = [h.system_uuid for h in host_risks if h.decision == 'review' and h.system_uuid]
        LOG.info(
            'risk scoring done cve=%s total_hosts=%d review_hosts=%d',
            cve_id,
            len(host_risks),
            len(review_uuids),
        )

        playbook_yaml = generate_playbook(cve_id, review_uuids)
        run_id = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
        playbook_path = f'playbooks/generated/{cve_id}-v3-{run_id}.yml'
        abs_playbook = WORKSPACE / playbook_path
        abs_playbook.parent.mkdir(parents=True, exist_ok=True)
        abs_playbook.write_text(playbook_yaml)

        repo_playbook = DEFAULT_AAP_PROJECT_CHECKOUT / playbook_path
        repo_playbook.parent.mkdir(parents=True, exist_ok=True)
        repo_playbook.write_text(playbook_yaml)
        LOG.info('playbook written path=%s bytes=%d', playbook_path, len(playbook_yaml))

        push_method = publish_playbook(DEFAULT_AAP_PROJECT_CHECKOUT, playbook_path, cve_id, playbook_yaml)
        sync_project(DEFAULT_PROJECT_ID)
        templates = create_templates(cve_id, playbook_path)
        launch_workflow_template(templates['workflow_template_id'])
        status = poll_latest_status(templates['workflow_template_id'], templates['job_template_id'])
        update_state(cve_id, cve_summary, playbook_path, host_risks, templates, status, push_method=push_method)

        result = {
            'cve': cve_id,
            'affected_hosts': len(host_risks),
            'review_hosts': [h.host for h in host_risks if h.decision == 'review'],
            'playbook_path': playbook_path,
            'playbook_push_method': push_method,
            'job_template_url': templates['job_template_ui_url'],
            'workflow_template_url': templates['workflow_template_ui_url'],
            'latest_workflow_job': status.get('latest_workflow_job'),
            'latest_job': status.get('latest_job'),
        }
        log_step('workflow_complete', cve=cve_id, playbook=playbook_path)
        print(json.dumps(result, indent=2))
        return 0
    except Exception:
        LOG.exception('workflow failed cve=%s', cve_id)
        raise


if __name__ == '__main__':
    raise SystemExit(main())
