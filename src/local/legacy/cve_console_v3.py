#!/usr/bin/env python3
import json
import os
import ssl
import subprocess
import sys
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)

_LEGACY_DIR = Path(__file__).resolve().parent
WORKSPACE = Path(os.environ.get('WORKSPACE', str(_LEGACY_DIR.parent)))
STATE_DIR = WORKSPACE / 'cve_console'
STATE_FILE = STATE_DIR / 'state.json'
DOTENV_FILE = STATE_DIR / '.env'
FLOW_SCRIPT = _LEGACY_DIR / 'cve_flow_v3.py'
FLOW_LOG = WORKSPACE / 'cve_console.log'
FLOW_PID = WORKSPACE / 'cve_console.pid'
load_dotenv(DOTENV_FILE)

if str(_LEGACY_DIR) not in sys.path:
    sys.path.insert(0, str(_LEGACY_DIR))
from cve_flow_v3 import invoke_tool

HOST = os.environ.get('CVE_CONSOLE_HOST', '127.0.0.1')
PORT = int(os.environ.get('CVE_CONSOLE_PORT', '8787'))
POLL_SECONDS = int(os.environ.get('CVE_CONSOLE_POLL_SECONDS', '30'))
AAP_VERIFY_TLS = os.environ.get('AAP_VERIFY_TLS', 'false').lower() in {'1', 'true', 'yes'}
LLAMA_URL = os.environ.get('LLAMA_STACK_URL', 'http://127.0.0.1:8321')


DEFAULT_STATE = {
    'workflow': {
        'name': 'CVE-2020-25681 remediation workflow',
        'cve': 'CVE-2020-25681',
        'status': 'review_pending',
        'last_updated': None,
        'polling': 'local_only',
    },
    'summary': {
        'mode': 'hybrid',
        'job_template_url': 'https://aap-aap.apps.cluster-pmh55.pmh55.sandbox1954.opentlc.com/api/controller/v2/job_templates/48/',
        'workflow_template_url': 'https://aap-aap.apps.cluster-pmh55.pmh55.sandbox1954.opentlc.com/api/controller/v2/workflow_job_templates/49/',
        'playbook_path': 'playbooks/generated/CVE-2020-25681-hybrid-20260403-165722.yml',
        'review_reason': 'Risk threshold exceeded (>30) for one or more affected hosts.',
        'approval_state': 'pending_review',
        'last_job_status': 'unknown',
        'last_workflow_status': 'unknown',
    },
    'stream': [
        {
            'time': '2026-04-03T16:57:22Z',
            'event': 'playbook_generated',
            'message': 'Hybrid remediation playbook generated and pushed to GitHub.',
        },
        {
            'time': '2026-04-03T16:57:22Z',
            'event': 'job_template_created',
            'message': 'AAP Job Template 48 created for remediation run.',
        },
        {
            'time': '2026-04-03T16:57:22Z',
            'event': 'workflow_template_created',
            'message': 'Approval-gated Workflow Job Template 49 created.',
        },
        {
            'time': '2026-04-03T16:57:22Z',
            'event': 'awaiting_review',
            'message': 'Workflow is ready for review before remediation execution.',
        },
    ],
    'hosts': [
        {
            'host': 'placeholder-host-1',
            'risk_score': 42,
            'decision': 'review',
            'reason': 'Kernel package update requires explicit approval.',
        }
    ],
    'aap': {
        'enabled': False,
        'base_url': None,
        'workflow_template_id': 49,
        'job_template_id': 48,
        'workflow_jobs_endpoint': None,
        'job_launch_endpoint': None,
        'last_poll': None,
        'last_error': 'AAP credentials not configured.',
        'latest_workflow_job': None,
        'latest_job': None,
    },
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def deep_copy_default_state() -> dict:
    return json.loads(json.dumps(DEFAULT_STATE))


def load_state() -> dict:
    if not STATE_FILE.exists():
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        state = deep_copy_default_state()
        state['workflow']['last_updated'] = now_iso()
        persist_state(state)
        return state
    state = json.loads(STATE_FILE.read_text())
    changed = ensure_state_shape(state)
    if changed:
        persist_state(state)
    return state


def ensure_state_shape(state: dict) -> bool:
    changed = False
    default = deep_copy_default_state()
    for section, value in default.items():
        if section not in state:
            state[section] = value
            changed = True
    for key, value in default['workflow'].items():
        if key not in state['workflow']:
            state['workflow'][key] = value
            changed = True
    for key, value in default['summary'].items():
        if key not in state['summary']:
            state['summary'][key] = value
            changed = True
    for key, value in default['aap'].items():
        if key not in state['aap']:
            state['aap'][key] = value
            changed = True
    if 'hosts' not in state or not isinstance(state['hosts'], list):
        state['hosts'] = default['hosts']
        changed = True
    if 'stream' not in state or not isinstance(state['stream'], list):
        state['stream'] = default['stream']
        changed = True
    return changed


def persist_state(state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2))


def add_stream_event(state: dict, event: str, message: str) -> None:
    if any(item.get('event') == event and item.get('message') == message for item in state['stream'][-10:]):
        return
    state['stream'].append({'time': now_iso(), 'event': event, 'message': message})
    state['stream'] = state['stream'][-100:]


def parse_template_id(url: str | None) -> int | None:
    if not url:
        return None
    parts = [p for p in url.strip('/').split('/') if p]
    for part in reversed(parts):
        if part.isdigit():
            return int(part)
    return None


def get_ssl_context():
    if AAP_VERIFY_TLS:
        return None
    return ssl._create_unverified_context()


def fetch_json(url: str, token: str) -> dict:
    req = urllib.request.Request(url)
    req.add_header('Authorization', f'Bearer {token}')
    req.add_header('Accept', 'application/json')
    with urllib.request.urlopen(req, timeout=10, context=get_ssl_context()) as resp:
        return json.loads(resp.read().decode())


def infer_aap_config(state: dict) -> bool:
    token = os.environ.get('AAP_TOKEN') or os.environ.get('CONTROLLER_OAUTH_TOKEN') or os.environ.get('AWX_TOKEN')
    base_url = os.environ.get('AAP_BASE_URL') or os.environ.get('AAP_URL') or os.environ.get('CONTROLLER_HOST') or os.environ.get('AWX_HOST')
    if base_url and '/api/controller/' in base_url:
        base_url = base_url.split('/api/controller/')[0]
    changed = False
    if not base_url:
        wf_url = state['summary'].get('workflow_template_url')
        if wf_url and '/api/controller/' in wf_url:
            base_url = wf_url.split('/api/controller/')[0]
    if base_url and state['aap'].get('base_url') != base_url:
        state['aap']['base_url'] = base_url
        changed = True
    if state['aap'].get('workflow_template_id') is None:
        wf_id = parse_template_id(state['summary'].get('workflow_template_url'))
        if wf_id is not None:
            state['aap']['workflow_template_id'] = wf_id
            changed = True
    if state['aap'].get('job_template_id') is None:
        jt_id = parse_template_id(state['summary'].get('job_template_url'))
        if jt_id is not None:
            state['aap']['job_template_id'] = jt_id
            changed = True
    state['aap']['enabled'] = bool(token and state['aap'].get('base_url'))
    if state['aap']['base_url'] and state['aap'].get('workflow_template_id'):
        state['aap']['workflow_jobs_endpoint'] = f"{state['aap']['base_url']}/api/controller/v2/workflow_jobs/?workflow_job_template={state['aap']['workflow_template_id']}&order_by=-id&page_size=1"
    if state['aap']['base_url'] and state['aap'].get('job_template_id'):
        state['aap']['job_launch_endpoint'] = f"{state['aap']['base_url']}/api/controller/v2/job_templates/{state['aap']['job_template_id']}/launch/"
    if not token:
        state['aap']['last_error'] = 'AAP token not configured. Set AAP_TOKEN (or CONTROLLER_OAUTH_TOKEN/AWX_TOKEN) to enable live polling.'
    elif not state['aap'].get('base_url'):
        state['aap']['last_error'] = 'AAP base URL not configured. Set AAP_BASE_URL (or CONTROLLER_HOST/AWX_HOST) to enable live polling.'
    return changed


def invoke_insights_get_cves(limit: int, offset: int) -> dict | None:
    try:
        payload = invoke_tool('vulnerability__get_cves', {
            'limit': limit,
            'offset': offset,
            'sort': '-public_date',
            'cvss_from': 0.0,
            'cvss_to': 10.0,
            'impact': '1,2,4,5,7',
            'rule_presence': 'true,false',
            'known_exploit': 'true,false',
            'advisory_available': 'true',
            'affecting_host_type': 'rpmdnf',
        })
    except Exception:
        return None
    text_parts = [item.get('text', '') for item in payload.get('content', []) or [] if item.get('text')]
    text = '\n'.join(text_parts).strip()
    candidates = [text]
    start_obj = text.find('{')
    end_obj = text.rfind('}')
    if start_obj != -1 and end_obj != -1 and end_obj >= start_obj:
        candidates.append(text[start_obj:end_obj + 1])
    for candidate in candidates:
        try:
            return json.loads(candidate)
        except Exception:
            continue
    return None


def fetch_cve_options() -> list[dict]:
    try:
        options = []
        seen = set()
        offset = 0
        limit = 100
        max_pages = 50
        for _ in range(max_pages):
            data = invoke_insights_get_cves(limit=limit, offset=offset)
            if not data:
                break
            rows = data.get('data', []) if isinstance(data, dict) else data
            if not rows:
                break
            for item in rows:
                cve_id = item.get('id') or item.get('cve') or item.get('synopsis')
                attrs = item.get('attributes', {}) if isinstance(item, dict) else {}
                if cve_id and cve_id not in seen:
                    seen.add(cve_id)
                    desc = attrs.get('description') or ''
                    affected = attrs.get('systems_affected')
                    suffix = f' | affected: {affected}' if affected is not None else ''
                    options.append({
                        'id': cve_id,
                        'label': f"{cve_id}{suffix} — {desc[:120]}".strip(),
                    })
            if len(rows) < limit:
                break
            offset += limit
        return options
    except Exception as e:
        state = load_state()
        state.setdefault('summary', {})['workflow_error'] = f'Failed to load CVE list: {e}'
        persist_state(state)
        return []


def start_patch_process(cve_id: str) -> dict:
    env = os.environ.copy()
    with open(FLOW_LOG, 'a') as log_f:
        log_f.write(f'{now_iso()} [cve-console] TRIGGER patch flow cve={cve_id}\n')
    proc = subprocess.Popen(
        ['python3', str(FLOW_SCRIPT), '--cve', cve_id],
        cwd=str(WORKSPACE),
        stdout=open(FLOW_LOG, 'a'),
        stderr=subprocess.STDOUT,
        env=env,
    )
    FLOW_PID.write_text(str(proc.pid))
    state = load_state()
    state['workflow']['cve'] = cve_id
    state['workflow']['status'] = 'starting'
    state['workflow']['last_updated'] = now_iso()
    state.setdefault('summary', {})['workflow_error'] = None
    add_stream_event(state, 'patch_process_started', f'Started v3 patch flow for {cve_id} (pid {proc.pid}).')
    persist_state(state)
    return {'ok': True, 'pid': proc.pid, 'cve': cve_id}


def refresh_run_from_aap(run: dict, token: str) -> dict:
    aap = run.get('aap', {}) or {}
    base_url = aap.get('base_url')
    wf_template_id = aap.get('workflow_template_id')
    job_template_id = aap.get('job_template_id')
    if not (token and base_url and wf_template_id):
        return run
    wf_endpoint = f"{base_url}/api/controller/v2/workflow_jobs/?workflow_job_template={wf_template_id}&order_by=-id&page_size=1"
    try:
        payload = fetch_json(wf_endpoint, token)
        results = payload.get('results', [])
        if results:
            latest = results[0]
            wf_status = latest.get('status', 'unknown')
            run.setdefault('aap', {})['latest_workflow_job'] = {
                'id': latest.get('id'),
                'name': latest.get('name'),
                'status': wf_status,
                'finished': latest.get('finished'),
                'started': latest.get('started'),
                'url': f"{base_url}{latest.get('url')}" if latest.get('url') else None,
            }
            run.setdefault('summary', {})['last_workflow_status'] = wf_status
            run.setdefault('workflow', {})['status'] = wf_status
            run['workflow']['last_updated'] = now_iso()
        if job_template_id:
            job_endpoint = f"{base_url}/api/controller/v2/jobs/?job_template={job_template_id}&order_by=-id&page_size=1"
            jobs_payload = fetch_json(job_endpoint, token)
            job_results = jobs_payload.get('results', [])
            if job_results:
                latest_job = job_results[0]
                run['aap']['latest_job'] = {
                    'id': latest_job.get('id'),
                    'name': latest_job.get('name'),
                    'status': latest_job.get('status'),
                    'finished': latest_job.get('finished'),
                    'started': latest_job.get('started'),
                    'url': f"{base_url}{latest_job.get('url')}" if latest_job.get('url') else None,
                }
                run['summary']['last_job_status'] = latest_job.get('status') or run['summary'].get('last_job_status') or 'unknown'
        wf_status = run.get('summary', {}).get('last_workflow_status') or run.get('workflow', {}).get('status')
        if wf_status in {'waiting', 'pending', 'new'}:
            run['summary']['approval_state'] = 'pending_review'
        elif wf_status in {'successful'}:
            run['summary']['approval_state'] = 'approved_and_completed'
        elif wf_status in {'failed', 'error', 'canceled'}:
            run['summary']['approval_state'] = 'execution_problem'
        else:
            run['summary']['approval_state'] = 'in_progress'
        run['aap']['last_error'] = None
        run['aap']['last_poll'] = now_iso()
    except Exception as e:
        run.setdefault('aap', {})['last_error'] = f'Polling error: {e}'
    return run


def refresh_aap_state(state: dict) -> dict:
    infer_aap_config(state)
    token = os.environ.get('AAP_TOKEN') or os.environ.get('CONTROLLER_OAUTH_TOKEN') or os.environ.get('AWX_TOKEN')
    if not state['aap']['enabled']:
        state['workflow']['polling'] = 'local_only'
        state['workflow']['last_updated'] = now_iso()
        persist_state(state)
        return state
    state = refresh_run_from_aap(state, token)
    runs = state.get('runs', [])
    if isinstance(runs, list) and runs:
        state['runs'] = [refresh_run_from_aap(run, token) for run in runs]
    persist_state(state)
    return state


HTML = '''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Agentic Patching Console</title>
  <style>
    :root {
      --bg: #0b1020;
      --panel: #151c33;
      --text: #e7ecff;
      --muted: #9aa7d1;
      --accent: #6ea8fe;
      --border: #2a355f;
    }
    body { margin: 0; font-family: Inter, system-ui, sans-serif; background: var(--bg); color: var(--text); }
    .wrap { max-width: 1400px; margin: 0 auto; padding: 24px; }
    h1 { margin-top: 0; }
    table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border); border-radius: 14px; overflow: hidden; }
    th, td { text-align: left; vertical-align: top; padding: 14px; border-bottom: 1px solid var(--border); }
    th { color: var(--muted); font-weight: 600; }
    tr:last-child td { border-bottom: none; }
    a { color: var(--accent); }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; word-break: break-word; }
    .muted { color: var(--muted); }
    ul { margin: 0; padding-left: 18px; }
    .empty { color: var(--muted); font-style: italic; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>Agentic Patching Console</h1>
    <div style="margin-bottom: 16px; display: flex; gap: 12px; align-items: center; flex-wrap: wrap;">
      <label for="cve_input" class="muted">CVE</label>
      <input id="cve_input" type="text" placeholder="Enter CVE ID, e.g. CVE-2020-25681" style="min-width: 420px; padding: 8px; background: var(--panel); color: var(--text); border: 1px solid var(--border); border-radius: 8px;" />
      <button id="start_btn" style="padding: 10px 14px; background: var(--accent); color: #081020; border: none; border-radius: 8px; font-weight: 700; cursor: pointer;">Start Patch Process</button>
      <span id="launch_status" class="muted"></span>
    </div>
    <div id="workflow_error" class="muted" style="margin-bottom: 12px;"></div>
    <table>
      <thead>
        <tr>
          <th>Triggered At</th>
          <th>CVE Name</th>
          <th>Affected Hosts list</th>
          <th>Information from RAG for hosts</th>
          <th>Ansible URL's</th>
          <th>Current Ansible Status</th>
        </tr>
      </thead>
      <tbody id="runs_table_body"></tbody>
    </table>
  </div>

<script>
function esc(v) {
  return (v === null || v === undefined || v === '') ? '—' : String(v);
}

function renderHosts(hosts) {
  if (!hosts || !hosts.length) return '<div class="empty">No hosts</div>';
  return `<ul>${hosts.map(h => `<li><strong>${esc(h.host)}</strong>${h.decision ? ` — ${esc(h.decision)}` : ''}</li>`).join('')}</ul>`;
}

function renderRag(hosts) {
  if (!hosts || !hosts.length) return '<div class="empty">No RAG info</div>';
  const items = hosts.map(h => {
    const ds = h.decision_support;
    let text = '';
    if (typeof ds === 'string') {
      text = ds;
    } else if (ds && typeof ds === 'object') {
      text = ds.answer || ds.summary || ds.text || JSON.stringify(ds, null, 2);
    }
    return `<li><strong>${esc(h.host)}</strong><br>${text ? `<span>${esc(text)}</span>` : '<span class="empty">No RAG info yet</span>'}</li>`;
  }).join('');
  return `<ul>${items}</ul>`;
}

function renderUrls(data) {
  const links = [];
  if (data.summary.job_template_url) {
    links.push(`<li><a target="_blank" rel="noreferrer" href="${data.summary.job_template_url}">Job Template</a></li>`);
  }
  if (data.summary.workflow_template_url) {
    links.push(`<li><a target="_blank" rel="noreferrer" href="${data.summary.workflow_template_url}">Workflow Template</a></li>`);
  }
  const wfJob = data.aap && data.aap.latest_workflow_job;
  if (wfJob && wfJob.url) {
    links.push(`<li><a target="_blank" rel="noreferrer" href="${wfJob.url}">Latest Workflow Job</a></li>`);
  }
  const job = data.aap && data.aap.latest_job;
  if (job && job.url) {
    links.push(`<li><a target="_blank" rel="noreferrer" href="${job.url}">Latest Job</a></li>`);
  }
  return links.length ? `<ul>${links.join('')}</ul>` : '<div class="empty">No URLs</div>';
}

function normalizeStatus(status, approvalState) {
  const s = (status || '').toLowerCase();
  if (!s && approvalState) return approvalState;
  if (s === 'successful') return 'successful';
  if (s === 'failed' || s === 'error' || s === 'canceled') return s;
  if (s === 'waiting' || s === 'pending' || s === 'new') return 'waiting_for_approval';
  if (s === 'running') return 'running';
  return status || 'unknown';
}

function renderStatus(data) {
  const parts = [];
  const wfJob = data.aap && data.aap.latest_workflow_job;
  const job = data.aap && data.aap.latest_job;
  const wfStatus = normalizeStatus((wfJob && wfJob.status) || data.summary.last_workflow_status || data.workflow.status, data.summary.approval_state);
  const jobStatus = normalizeStatus(job && job.status, null);
  parts.push(`<div><strong>Workflow:</strong> ${esc(wfStatus)}</div>`);
  if (job || data.summary.last_job_status) {
    parts.push(`<div><strong>Job:</strong> ${esc(jobStatus || data.summary.last_job_status)}</div>`);
  }
  if (data.summary && data.summary.approval_state) {
    parts.push(`<div><strong>Approval:</strong> ${esc(data.summary.approval_state)}</div>`);
  }
  if (wfJob && wfJob.finished) {
    parts.push(`<div><strong>Workflow finished:</strong> ${esc(wfJob.finished)}</div>`);
  }
  if (job && job.finished) {
    parts.push(`<div><strong>Job finished:</strong> ${esc(job.finished)}</div>`);
  }
  if (data.summary && data.summary.workflow_error) {
    parts.push(`<div style="margin-top:8px;color:#ffb4b4;"><strong>Error:</strong> ${esc(data.summary.workflow_error)}</div>`);
  }
  if (data.aap && data.aap.last_error) {
    parts.push(`<div style="margin-top:8px;color:#ffb4b4;"><strong>AAP:</strong> ${esc(data.aap.last_error)}</div>`);
  }
  return parts.join('');
}

async function startPatch() {
  const cve = document.getElementById('cve_input').value.trim();
  const btn = document.getElementById('start_btn');
  const status = document.getElementById('launch_status');
  btn.disabled = true;
  status.textContent = `Starting ${cve}...`;
  try {
    const res = await fetch('/api/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({cve})
    });
    const data = await res.json();
    status.textContent = data.ok ? `Started ${data.cve}` : 'Failed to start';
  } catch (e) {
    status.textContent = `Start failed: ${e}`;
  } finally {
    btn.disabled = false;
  }
  await refresh();
}

function renderRow(run) {
  return `
    <tr>
      <td>${esc(run.workflow && run.workflow.triggered_at)}</td>
      <td>${esc(run.workflow && run.workflow.cve)}</td>
      <td>${renderHosts(run.hosts || [])}</td>
      <td>${renderRag(run.hosts || [])}</td>
      <td>${renderUrls(run)}</td>
      <td>${renderStatus(run)}</td>
    </tr>`;
}

async function refresh() {
  const res = await fetch('/api/state');
  const data = await res.json();
  const runs = (data.runs && data.runs.length) ? data.runs : [{workflow: data.workflow, hosts: data.hosts, summary: data.summary, aap: data.aap}];
  document.getElementById('runs_table_body').innerHTML = runs.map(renderRow).join('');
  document.getElementById('workflow_error').textContent = (data.summary && data.summary.workflow_error) ? `Workflow error for ${data.workflow.cve}: ${data.summary.workflow_error}` : '';
}

document.getElementById('start_btn').addEventListener('click', startPatch);
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
'''


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == '/api/state':
            state = refresh_aap_state(load_state())
            body = json.dumps(state).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == '/api/cves':
            body = json.dumps({'cves': fetch_cve_options()}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == '/' or parsed.path == '/index.html':
            body = HTML.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == '/healthz':
            body = b'ok'
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == '/api/start':
            length = int(self.headers.get('Content-Length', '0') or '0')
            raw = self.rfile.read(length) if length else b'{}'
            try:
                payload = json.loads(raw.decode() or '{}')
                cve = payload.get('cve')
                if not cve:
                    raise ValueError('Missing cve')
                result = start_patch_process(cve)
                body = json.dumps(result).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            except Exception as e:
                body = json.dumps({'ok': False, 'error': str(e)}).encode()
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        return


if __name__ == '__main__':
    state = load_state()
    refresh_aap_state(state)
    server = HTTPServer((HOST, PORT), Handler)
    print(f'CVE console listening on http://{HOST}:{PORT}')
    server.serve_forever()
