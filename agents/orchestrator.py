# SolGuard AI - Master Orchestrator
# Coordinates all 5 phases of the multi-agentic audit pipeline

import argparse, json, os, sys
from pathlib import Path
from typing import Dict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('SolGuardOrchestrator')
sys.path.insert(0, str(Path(__file__).parent))


class SolGuardOrchestrator:
    """Master coordinator for SolGuard AI 5-phase audit pipeline."""

    def __init__(self, output_base='./output'):
        self.output_base = Path(output_base)
        self.output_base.mkdir(parents=True, exist_ok=True)
        self.agents = self._init_agents()

    def _init_agents(self):
        agents = {}
        phases = [
            ('parser',     'phase1_lexical.parsing_agent', 'ParsingAgent',           {'output_dir': str(self.output_base/'phase1')}),
            ('static',     'phase1_lexical.static_agent',  'StaticAnalysisAgent',    {'output_dir': str(self.output_base/'phase1')}),
            ('classifier', 'phase2_neural.risk_classifier', 'RiskClassificationAgent', {'output_dir': str(self.output_base/'phase2')}),
            ('reasoner',   'phase3_semantic.reasoning_agent', 'ReasoningAgent',       {'output_dir': str(self.output_base/'phase3')}),
            ('patcher',    'phase4_patching.patch_agent',  'PatchAgent',             {'output_dir': str(self.output_base/'phase4')}),
        ]
        for key, module, cls, kwargs in phases:
            try:
                mod = __import__(module, fromlist=[cls])
                agents[key] = getattr(mod, cls)(**kwargs)
                logger.info(f'Agent loaded: {key}')
            except Exception as e:
                logger.warning(f'Agent {key} unavailable: {e}')
        return agents

    def audit(self, sol_file: str, phases: str = 'all') -> Dict:
        sol_path = Path(sol_file)
        if not sol_path.exists():
            raise FileNotFoundError(f'Contract not found: {sol_file}')

        run_phases = set(range(1, 5)) if phases == 'all' else {int(p) for p in phases.split(',')}
        report = {'contract': str(sol_path), 'name': sol_path.stem, 'results': {}}

        logger.info(f'\n=== SolGuard AI Audit: {sol_path.name} ===')

        if 1 in run_phases:
            logger.info('[Phase 1] Lexical Observer')
            p1 = {}
            if 'parser' in self.agents:
                try: p1['ast'] = self.agents['parser'].parse_contract(sol_file)
                except Exception as e: logger.error(f'Parser: {e}')
            if 'static' in self.agents:
                try: p1['static'] = self.agents['static'].analyze(sol_file)
                except Exception as e: logger.error(f'Static: {e}')
            report['results']['phase1'] = p1

        if 2 in run_phases and 'phase1' in report['results']:
            logger.info('[Phase 2] Neural Auditor')
            if 'classifier' in self.agents:
                try:
                    p1 = report['results']['phase1']
                    report['results']['phase2'] = self.agents['classifier'].classify(
                        p1.get('static', {}), p1.get('ast', {})
                    )
                except Exception as e: logger.error(f'Classifier: {e}')

        if 3 in run_phases and 'phase2' in report['results']:
            logger.info('[Phase 3] Semantic Architect')
            if 'reasoner' in self.agents:
                try:
                    report['results']['phase3'] = self.agents['reasoner'].reason(
                        report['results']['phase2'], sol_file
                    )
                except Exception as e: logger.error(f'Reasoner: {e}')

        if 4 in run_phases:
            logger.info('[Phase 4] Patching Agent')
            if 'patcher' in self.agents:
                src = report['results'].get('phase3', report['results'].get('phase2', {}))
                if src:
                    try:
                        report['results']['phase4'] = self.agents['patcher'].generate_patches(src, sol_file)
                    except Exception as e: logger.error(f'Patcher: {e}')

        # Summary
        p1s = report['results'].get('phase1', {}).get('static', {}).get('summary', {})
        p2 = report['results'].get('phase2', {})
        p4 = report['results'].get('phase4', {})
        report['summary'] = {
            'total_findings': p1s.get('total', 0),
            'overall_risk': p2.get('overall_risk', {}).get('label', 'UNKNOWN'),
            'grade': p2.get('overall_risk', {}).get('grade', '?'),
            'patches': p4.get('patch_count', 0),
        }

        out = self.output_base / f"{sol_path.stem}_full_report.json"
        with open(out, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        s = report['summary']
        print(f"\n{'='*50}\n SolGuard AI | {sol_path.name}\n{'='*50}")
        print(f" Findings: {s['total_findings']} | Risk: {s['overall_risk']} | Grade: {s['grade']} | Patches: {s['patches']}")
        print(f" Report: {out}\n{'='*50}")
        return report


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description='SolGuard AI - Autonomous Smart Contract Auditor')
    ap.add_argument('--contract', required=True)
    ap.add_argument('--phases', default='all')
    ap.add_argument('--output', default='./output')
    ap.add_argument('--llm', default='openai')
    args = ap.parse_args()
    os.environ.setdefault('LLM_PROVIDER', args.llm)
    SolGuardOrchestrator(output_base=args.output).audit(args.contract, args.phases)
