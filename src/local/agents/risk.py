from __future__ import annotations

from typing import Any

from a2a.messages import AgentMessage
from agents.base import BaseAgent


class RiskAgent(BaseAgent):
    name = 'risk'

    def __init__(self, bus, *, flow_module):
        super().__init__(bus)
        self._flow = flow_module

    def on_score_hosts(self, msg: AgentMessage) -> AgentMessage:
        systems = msg.payload['systems']
        cvss = msg.payload['cvss']
        affected_count = msg.payload['affected_count']
        cve_id = msg.payload['cve_id']
        vector_db_id = msg.payload.get('vector_db_id', self._flow.DEFAULT_VECTOR_DB_ID)

        self.log.info('Scoring %d hosts for %s', len(systems), cve_id)
        self.emit('stage_update', {'message': f'Risk Agent scoring {len(systems)} hosts with RHOAI predictive model'})

        host_risks = []
        for sys_item in systems:
            sattrs = sys_item.get('attributes', {})
            host_name = sattrs.get('display_name') or sys_item.get('id') or 'unknown-host'
            uuid = sys_item.get('id') or sattrs.get('id') or sattrs.get('inventory_id')
            age_days = self._flow.age_days_from_timestamp(sattrs.get('first_reported'))
            score = round(self._flow.risk_score(cvss, age_days, affected_count, 'security'), 2)
            decision = 'review' if score > 30 else 'ok'
            reason = 'Kernel package update requires explicit approval.' if decision == 'review' else 'Below risk threshold.'

            decision_support = None
            if decision == 'review':
                self.emit('stage_update', {'message': f'Risk Agent running RAG analysis for {host_name} (score={score})'})
                decision_support = self._flow.rag_summary_for_host(host_name, vector_db_id)

            host_risks.append(self._flow.HostRisk(
                host=host_name,
                system_uuid=uuid,
                age_days=age_days,
                risk_score=score,
                decision=decision,
                reason=reason,
                decision_support=decision_support,
            ))

        review_hosts = [h for h in host_risks if h.decision == 'review']
        self.log.info('Scoring done: %d total, %d require review', len(host_risks), len(review_hosts))

        return msg.reply({
            'message': f'Risk assessment complete — {len(review_hosts)} hosts require review',
            'host_risks': host_risks,
            'review_count': len(review_hosts),
            'total_count': len(host_risks),
        })

    def on_explain_risk(self, msg: AgentMessage) -> AgentMessage:
        host = msg.payload['host']
        vector_db_id = msg.payload.get('vector_db_id', self._flow.DEFAULT_VECTOR_DB_ID)
        self.emit('stage_update', {'message': f'Risk Agent explaining risk decision for {host}'})
        summary = self._flow.rag_summary_for_host(host, vector_db_id)
        return msg.reply({
            'message': f'Risk explanation for {host}',
            'host': host,
            'explanation': summary,
        })
