from __future__ import annotations

from typing import Any

from a2a.messages import AgentMessage
from agents.base import BaseAgent


class DiagnosisAgent(BaseAgent):
    name = 'diagnosis'

    def __init__(self, bus, *, flow_module):
        super().__init__(bus)
        self._flow = flow_module

    def on_analyze_failure(self, msg: AgentMessage) -> AgentMessage:
        host = msg.payload['host']
        error = msg.payload.get('error', 'Unknown failure')
        cve_id = msg.payload.get('cve_id', '')
        vector_db_id = msg.payload.get('vector_db_id', self._flow.DEFAULT_VECTOR_DB_ID)

        self.log.info('Analyzing failure on %s for %s', host, cve_id)
        self.emit('stage_update', {'message': f'Diagnosis Agent analyzing failure on {host}'})

        rag_result = self._flow.rag_summary_for_host(host, vector_db_id)

        prompt = (
            f'A patch for {cve_id} failed on host {host}. Error: {error}. '
            f'Historical context: {rag_result.get("summary", "No history available")}. '
            'Analyze the likely root cause and recommend a specific remediation action. '
            'Be concise — 2-3 sentences for cause, 1-2 for remediation.'
        )
        try:
            analysis = self._flow.http_json(
                f'{self._flow.LLAMA_URL}/v1/responses',
                method='POST',
                payload={
                    'model': self._flow.DEFAULT_LLM_MODEL,
                    'input': [{'role': 'user', 'content': prompt}],
                    'stream': False,
                },
                headers={'Content-Type': 'application/json'},
                verify_tls=True,
            )
            text = ''
            for item in analysis.get('output', []):
                for content in item.get('content', []):
                    if content.get('text'):
                        text = content['text'].strip()
                        break
                if text:
                    break
            if not text:
                text = 'LLM analysis returned no text.'
        except Exception as exc:
            text = f'LLM analysis unavailable: {exc}'

        return msg.reply({
            'message': f'Failure analysis for {host}',
            'host': host,
            'error': error,
            'analysis': text,
            'history': rag_result.get('summary', ''),
            'recommendation': text.split('.')[-2] + '.' if '.' in text else text,
        })

    def on_propose_remediation(self, msg: AgentMessage) -> AgentMessage:
        host = msg.payload['host']
        analysis = msg.payload.get('analysis', '')
        self.emit('stage_update', {'message': f'Diagnosis Agent proposing remediation for {host}'})

        return msg.reply({
            'message': f'Remediation proposed for {host}',
            'host': host,
            'remediation': {
                'problem': msg.payload.get('error', 'Patch failure'),
                'proposed_change': analysis,
                'risk': 'Medium',
                'approval_required': True,
                'status': 'proposed',
            },
        })
