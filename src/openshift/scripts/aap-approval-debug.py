#!/usr/bin/env python3
"""Print AAP workflow approval discovery details for a workflow job id."""
import json
import os
import ssl
import sys
import urllib.error
import urllib.request


def main() -> int:
    wf_job_id = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    if not wf_job_id:
        print('usage: aap-approval-debug.py <workflow_job_id>', file=sys.stderr)
        return 2
    raw_base = os.environ.get('AAP_BASE_URL', '')
    base = raw_base.split('/api/controller/')[0].rstrip('/')
    token = os.environ.get('AAP_TOKEN') or os.environ.get('CONTROLLER_OAUTH_TOKEN') or os.environ.get('AWX_TOKEN')
    if not base or not token:
        print('AAP_BASE_URL and AAP_TOKEN required', file=sys.stderr)
        return 2
    ctx = ssl._create_unverified_context()

    def get(path: str):
        url = f'{base}{path}'
        req = urllib.request.Request(url, headers={'Authorization': f'Bearer {token}', 'Accept': 'application/json'})
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
                return resp.status, json.load(resp)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode()
            return exc.code, body

    print(f'base={base}')
    print(f'workflow_job_id={wf_job_id}')
    print('\n== workflow job ==')
    print(json.dumps(get(f'/api/controller/v2/workflow_jobs/{wf_job_id}/'), indent=2))
    print('\n== workflow nodes ==')
    print(json.dumps(get(f'/api/controller/v2/workflow_jobs/{wf_job_id}/workflow_nodes/'), indent=2))
    print('\n== pending approvals (filtered) ==')
    print(json.dumps(get(f'/api/controller/v2/workflow_approvals/?source_workflow_job={wf_job_id}&status=pending'), indent=2))
    print('\n== all pending approvals ==')
    print(json.dumps(get('/api/controller/v2/workflow_approvals/?status=pending&page_size=20'), indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
