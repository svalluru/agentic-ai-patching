from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from a2a.messages import AgentMessage
from agents.base import BaseAgent


class AutomationAgent(BaseAgent):
    name = 'automation'

    def __init__(self, bus, *, flow_module):
        super().__init__(bus)
        self._flow = flow_module

    def on_generate_playbook(self, msg: AgentMessage) -> AgentMessage:
        cve_id = msg.payload['cve_id']
        review_uuids = msg.payload['review_uuids']
        self.log.info('Generating playbook for %s (%d hosts)', cve_id, len(review_uuids))
        self.emit('stage_update', {'message': f'Automation Agent generating remediation playbook for {cve_id}'})

        playbook_yaml = self._flow.generate_playbook(cve_id, review_uuids)
        run_id = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
        playbook_path = f'playbooks/generated/{cve_id}-v3-{run_id}.yml'

        abs_playbook = self._flow.WORKSPACE / playbook_path
        abs_playbook.parent.mkdir(parents=True, exist_ok=True)
        abs_playbook.write_text(playbook_yaml)

        repo_playbook = self._flow.DEFAULT_AAP_PROJECT_CHECKOUT / playbook_path
        repo_playbook.parent.mkdir(parents=True, exist_ok=True)
        repo_playbook.write_text(playbook_yaml)

        return msg.reply({
            'message': f'Playbook generated: {playbook_path}',
            'playbook_yaml': playbook_yaml,
            'playbook_path': playbook_path,
        })

    def on_publish_playbook(self, msg: AgentMessage) -> AgentMessage:
        cve_id = msg.payload['cve_id']
        playbook_yaml = msg.payload['playbook_yaml']
        playbook_path = msg.payload['playbook_path']
        repo_root = self._flow.DEFAULT_AAP_PROJECT_CHECKOUT
        self.emit('stage_update', {'message': f'Automation Agent publishing playbook to GitHub'})

        push_method = self._flow.publish_playbook(repo_root, playbook_path, cve_id, playbook_yaml)
        return msg.reply({
            'message': f'Playbook published via {push_method}',
            'push_method': push_method,
        })

    def on_sync_project(self, msg: AgentMessage) -> AgentMessage:
        self.emit('stage_update', {'message': 'Automation Agent syncing AAP project from GitHub'})
        self._flow.sync_project(self._flow.DEFAULT_PROJECT_ID)
        return msg.reply({'message': 'AAP project synced'})

    def on_create_templates(self, msg: AgentMessage) -> AgentMessage:
        cve_id = msg.payload['cve_id']
        playbook_path = msg.payload['playbook_path']
        self.emit('stage_update', {'message': 'Automation Agent creating AAP job and workflow templates'})

        templates = self._flow.create_templates(cve_id, playbook_path)
        return msg.reply({
            'message': f'Templates created (workflow={templates["workflow_template_id"]})',
            'templates': templates,
        })

    def on_launch_workflow(self, msg: AgentMessage) -> AgentMessage:
        workflow_template_id = msg.payload['workflow_template_id']
        self.emit('stage_update', {'message': 'Automation Agent launching AAP workflow'})

        self._flow.launch_workflow_template(workflow_template_id)
        return msg.reply({
            'message': f'Workflow {workflow_template_id} launched',
        })

    def on_poll_status(self, msg: AgentMessage) -> AgentMessage:
        workflow_template_id = msg.payload['workflow_template_id']
        job_template_id = msg.payload['job_template_id']
        status = self._flow.poll_latest_status(workflow_template_id, job_template_id)
        return msg.reply({
            'message': 'Status polled',
            'status': status,
        })
