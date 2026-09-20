from __future__ import annotations

import json
import logging
from dataclasses import asdict
from typing import Any

from a2a.messages import AgentMessage, MessageType
from agents.base import BaseAgent

LOG = logging.getLogger('agent.patch_manager')


class PatchManagerAgent(BaseAgent):
    """Orchestrator that delegates to specialist agents via the message bus."""

    name = 'patch_manager'

    def __init__(self, bus, *, flow_module):
        super().__init__(bus)
        self._flow = flow_module

    def on_run_flow(self, msg: AgentMessage) -> AgentMessage:
        cve_id = msg.payload['cve_id']
        triggered_at = msg.payload.get('triggered_at')
        self.log.info('Starting patch flow for %s', cve_id)

        self._flow.update_state_progress(cve_id, 'workflow_start')

        try:
            result = self._execute_flow(cve_id)
            return msg.reply({
                'message': f'Patch flow complete for {cve_id}',
                'result': result,
            })
        except Exception as exc:
            self.log.exception('Patch flow failed for %s', cve_id)
            self._flow.update_state_failure(cve_id, str(exc))
            return msg.error(str(exc))

    def _execute_flow(self, cve_id: str) -> dict[str, Any]:
        self._flow.update_state_progress(cve_id, 'loading_cve')
        vuln_resp = self.ask('vulnerability', 'fetch_cve', {'cve_id': cve_id})
        if vuln_resp and vuln_resp.msg_type == MessageType.ERROR:
            raise RuntimeError(vuln_resp.payload.get('error', 'Vulnerability fetch failed'))

        cve_data = vuln_resp.payload['cve_data']
        systems = vuln_resp.payload['systems']
        cvss = vuln_resp.payload['cvss']
        cve_summary = vuln_resp.payload['description']
        affected_count = vuln_resp.payload['affected_count']

        if self._flow.STATE_FILE.exists():
            self._enrich_state_with_cve(cve_id, cvss, affected_count, cve_summary, systems)

        self._flow.update_state_progress(cve_id, 'scoring_hosts')
        risk_resp = self.ask('risk', 'score_hosts', {
            'systems': systems,
            'cvss': cvss,
            'affected_count': affected_count,
            'cve_id': cve_id,
        })
        if risk_resp and risk_resp.msg_type == MessageType.ERROR:
            raise RuntimeError(risk_resp.payload.get('error', 'Risk scoring failed'))

        host_risks = risk_resp.payload['host_risks']
        review_uuids = [h.system_uuid for h in host_risks if h.decision == 'review' and h.system_uuid]
        self._flow.update_state_progress(
            cve_id, 'scoring_hosts',
            hosts=self._flow._hosts_for_progress(host_risks),
        )

        self._flow.update_state_progress(cve_id, 'generating_playbook')
        gen_resp = self.ask('automation', 'generate_playbook', {
            'cve_id': cve_id,
            'review_uuids': review_uuids,
        })
        if gen_resp and gen_resp.msg_type == MessageType.ERROR:
            raise RuntimeError(gen_resp.payload.get('error', 'Playbook generation failed'))

        playbook_yaml = gen_resp.payload['playbook_yaml']
        playbook_path = gen_resp.payload['playbook_path']

        self._flow.update_state_progress(cve_id, 'publishing_playbook')
        pub_resp = self.ask('automation', 'publish_playbook', {
            'cve_id': cve_id,
            'playbook_yaml': playbook_yaml,
            'playbook_path': playbook_path,
        })
        if pub_resp and pub_resp.msg_type == MessageType.ERROR:
            raise RuntimeError(pub_resp.payload.get('error', 'Playbook publish failed'))
        push_method = pub_resp.payload['push_method']

        self._flow.update_state_progress(cve_id, 'syncing_aap_project')
        sync_resp = self.ask('automation', 'sync_project', {})
        if sync_resp and sync_resp.msg_type == MessageType.ERROR:
            raise RuntimeError(sync_resp.payload.get('error', 'AAP sync failed'))

        self._flow.update_state_progress(cve_id, 'creating_aap_templates')
        tmpl_resp = self.ask('automation', 'create_templates', {
            'cve_id': cve_id,
            'playbook_path': playbook_path,
        })
        if tmpl_resp and tmpl_resp.msg_type == MessageType.ERROR:
            raise RuntimeError(tmpl_resp.payload.get('error', 'Template creation failed'))
        templates = tmpl_resp.payload['templates']

        self._flow.update_state_progress(cve_id, 'launching_workflow')
        launch_resp = self.ask('automation', 'launch_workflow', {
            'workflow_template_id': templates['workflow_template_id'],
        })
        if launch_resp and launch_resp.msg_type == MessageType.ERROR:
            raise RuntimeError(launch_resp.payload.get('error', 'Workflow launch failed'))

        self._flow.update_state_progress(cve_id, 'awaiting_aap')
        poll_resp = self.ask('automation', 'poll_status', {
            'workflow_template_id': templates['workflow_template_id'],
            'job_template_id': templates['job_template_id'],
        })
        status = poll_resp.payload['status'] if poll_resp else {}

        self._flow.update_state(
            cve_id, cve_summary, playbook_path,
            host_risks, templates, status,
            push_method=push_method,
        )

        self.bus.flush_to_state()

        return {
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

    def _enrich_state_with_cve(self, cve_id, cvss, affected_count, cve_summary, systems):
        state = json.loads(self._flow.STATE_FILE.read_text())
        for section in [state.get('summary', {})] + [r.get('summary', {}) for r in state.get('runs', [])[:1]]:
            section['cvss'] = cvss
            section['affected_count'] = affected_count
            section['cve_summary'] = cve_summary
        state['hosts'] = [
            {
                'host': (s.get('attributes') or {}).get('display_name') or s.get('id') or 'unknown-host',
                'system_uuid': s.get('id') or (s.get('attributes') or {}).get('inventory_id'),
                'age_days': self._flow.age_days_from_timestamp((s.get('attributes') or {}).get('first_reported')),
            }
            for s in systems
        ]
        self._flow.STATE_FILE.write_text(json.dumps(state, indent=2))
