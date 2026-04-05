"""
Phase 1: Lexical Observer - Static Analysis Agent
SolGuard AI - Autonomous Smart Contract Auditing Platform

Integrates with Slither to detect vulnerabilities:
- Reentrancy attacks (CWE-841)
- Uninitialized storage pointers (CWE-457)
- Integer overflow/underflow (CWE-190)
- Access control issues (CWE-284)
- Weak PRNG (CWE-338)
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Any
import logging

logger = logging.getLogger('StaticAgent')
logging.basicConfig(level=logging.INFO)

VULNERABILITY_REGISTRY = {
    'reentrancy-eth': {'severity': 'HIGH', 'cwe': 'CWE-841'},
    'uninitialized-storage': {'severity': 'HIGH', 'cwe': 'CWE-457'},
    'suicidal': {'severity': 'HIGH', 'cwe': 'CWE-284'},
    'arbitrary-send-eth': {'severity': 'HIGH', 'cwe': 'CWE-284'},
    'controlled-delegatecall': {'severity': 'HIGH', 'cwe': 'CWE-829'},
    'integer-overflow': {'severity': 'HIGH', 'cwe': 'CWE-190'},
    'tx-origin': {'severity': 'MEDIUM', 'cwe': 'CWE-284'},
    'weak-prng': {'severity': 'HIGH', 'cwe': 'CWE-338'},
    'locked-ether': {'severity': 'MEDIUM', 'cwe': 'CWE-400'},
}


class StaticAnalysisAgent:
    """
    Phase 1 Static Analysis Agent.
    Uses Slither (or pattern fallback) to find vulnerabilities.
    """

    def __init__(self, output_dir: str = './output/phase1'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.slither_available = self._check_slither()

    def _check_slither(self) -> bool:
        try:
            result = subprocess.run(['slither', '--version'], capture_output=True, timeout=5)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def analyze(self, sol_file_path: str) -> Dict[str, Any]:
        sol_path = Path(sol_file_path)
        logger.info(f'[StaticAgent] Analyzing: {sol_path.name}')
        findings = []

        if self.slither_available:
            findings.extend(self._run_slither(sol_path))
        else:
            findings.extend(self._pattern_analysis(sol_path))

        findings.extend(self._run_solhint(sol_path))
        findings = self._deduplicate(findings)
        findings.sort(key=lambda x: {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}.get(x.get('severity', 'LOW'), 2))

        result = {
            'contract_file': str(sol_path),
            'static_findings': findings,
            'summary': {
                'total': len(findings),
                'high': sum(1 for f in findings if f.get('severity') == 'HIGH'),
                'medium': sum(1 for f in findings if f.get('severity') == 'MEDIUM'),
                'low': sum(1 for f in findings if f.get('severity') == 'LOW'),
            },
            'slither_used': self.slither_available,
            'phase': 1,
            'agent': 'StaticAnalysisAgent'
        }

        output_file = self.output_dir / f"{sol_path.stem}_static.json"
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)

        return result

    def _run_slither(self, sol_path: Path) -> List[Dict]:
        findings = []
        try:
            cmd = ['slither', str(sol_path), '--json', '-']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.stdout:
                data = json.loads(result.stdout)
                for d in data.get('results', {}).get('detectors', []):
                    check = d.get('check', '')
                    info = VULNERABILITY_REGISTRY.get(check, {})
                    elements = d.get('elements', [])
                    findings.append({
                        'id': check,
                        'title': d.get('description', check).split('\n')[0][:100],
                        'severity': d.get('impact', info.get('severity', 'LOW')).upper(),
                        'confidence': d.get('confidence', 'Medium'),
                        'cwe': info.get('cwe', 'CWE-000'),
                        'lines': [e.get('source_mapping', {}).get('lines', []) for e in elements],
                        'tool': 'slither'
                    })
        except Exception as e:
            logger.error(f'Slither error: {e}')
        return findings

    def _pattern_analysis(self, sol_path: Path) -> List[Dict]:
        import re
        source = sol_path.read_text()
        lines = source.splitlines()
        findings = []
        PATTERNS = [
            (r'\.call\s*\{?\s*value\s*:', 'reentrancy-eth', 'Potential reentrancy via .call{value}', 'HIGH', 'CWE-841'),
            (r'tx\.origin', 'tx-origin', 'Dangerous tx.origin for auth', 'MEDIUM', 'CWE-284'),
            (r'block\.(timestamp|difficulty)', 'weak-prng', 'Weak PRNG from block vars', 'HIGH', 'CWE-338'),
            (r'selfdestruct|suicide\(', 'suicidal', 'Contract self-destruct', 'HIGH', 'CWE-284'),
            (r'delegatecall', 'controlled-delegatecall', 'Delegatecall detected', 'HIGH', 'CWE-829'),
            (r'assembly\s*\{', 'assembly', 'Inline assembly usage', 'LOW', 'CWE-676'),
        ]
        for pattern, vuln_id, title, severity, cwe in PATTERNS:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append({
                        'id': vuln_id, 'title': title, 'severity': severity,
                        'cwe': cwe, 'lines': [i], 'line_content': line.strip(), 'tool': 'pattern'
                    })
                    break
        return findings

    def _run_solhint(self, sol_path: Path) -> List[Dict]:
        findings = []
        try:
            result = subprocess.run(['solhint', '--reporter', 'json', str(sol_path)],
                                    capture_output=True, text=True, timeout=30)
            if result.stdout:
                data = json.loads(result.stdout)
                for fr in (data if isinstance(data, list) else [data]):
                    for msg in fr.get('messages', []):
                        findings.append({
                            'id': f'solhint-{msg.get("ruleId","")}',
                            'title': msg.get('message', ''),
                            'severity': 'MEDIUM' if msg.get('severity') == 2 else 'LOW',
                            'lines': [msg.get('line', 0)], 'tool': 'solhint', 'cwe': 'CWE-710'
                        })
        except Exception:
            pass
        return findings

    def _deduplicate(self, findings: List[Dict]) -> List[Dict]:
        seen, unique = set(), []
        for f in findings:
            key = (f.get('id'), str(f.get('lines', [])))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python static_agent.py <contract.sol>')
        sys.exit(1)
    agent = StaticAnalysisAgent()
    result = agent.analyze(sys.argv[1])
    s = result['summary']
    print(f'[SolGuard AI] Static Analysis | HIGH:{s["high"]} MEDIUM:{s["medium"]} LOW:{s["low"]}')
    for f in result['static_findings']:
        print(f'  [{f["severity"]}] {f["title"]} | {f["cwe"]} | Line {f.get("lines",["-"])[0]}')
