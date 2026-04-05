"""
Phase 1 - Solhint Runner: Lints Solidity contracts for best practice violations.
"""
import subprocess
import json
import tempfile
import os
import re


class SolhintRunner:
    """Wraps Solhint linter. Falls back to regex patterns if solhint not installed."""

    PATTERNS = [
        (r'\.call\{value:', 'avoid-call-value', 'High', 'Use transfer/send instead of call{value:}'),
        (r'assembly\s*\{', 'no-inline-assembly', 'Medium', 'Avoid inline assembly'),
        (r'\.call\(', 'avoid-low-level-calls', 'Medium', 'Avoid low-level calls'),
        (r'block\.timestamp', 'not-rely-on-time', 'Low', 'Avoid relying on block.timestamp'),
        (r'tx\.origin', 'avoid-tx-origin', 'High', 'Never use tx.origin for auth'),
        (r'selfdestruct|suicide', 'avoid-suicide', 'High', 'selfdestruct is dangerous'),
        (r'delegatecall', 'no-delegatecall', 'High', 'delegatecall is dangerous'),
    ]

    def __init__(self, solhint_path='solhint'):
        self.solhint_path = solhint_path

    def run(self, source_code: str) -> dict:
        """Lint source code, returns dict with issues and summary."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False, encoding='utf-8') as tmp:
            tmp.write(source_code)
            tmp_path = tmp.name
        try:
            return self._execute_solhint(tmp_path, source_code)
        finally:
            os.unlink(tmp_path)

    def _execute_solhint(self, file_path: str, source_code: str) -> dict:
        try:
            result = subprocess.run(
                [self.solhint_path, '--formatter', 'json', file_path],
                capture_output=True, text=True, timeout=30
            )
            if result.stdout.strip():
                data = json.loads(result.stdout)
                issues = []
                for f in data:
                    for msg in f.get('messages', []):
                        issues.append({
                            'tool': 'solhint',
                            'type': msg.get('ruleId', 'unknown'),
                            'severity': 'High' if msg.get('severity') == 2 else 'Low',
                            'line': msg.get('line', 0),
                            'message': msg.get('message', ''),
                        })
                return self._build_result(issues)
        except FileNotFoundError:
            pass
        except Exception:
            pass
        return self._fallback_lint(source_code)

    def _fallback_lint(self, source_code: str) -> dict:
        """Regex-based fallback when solhint is not available."""
        issues = []
        for i, line in enumerate(source_code.split('\n'), 1):
            for pattern, rule, severity, message in self.PATTERNS:
                if re.search(pattern, line):
                    issues.append({'tool': 'solhint-fallback', 'type': rule, 'severity': severity, 'line': i, 'message': message})
        result = self._build_result(issues)
        result['note'] = 'solhint not installed - using pattern fallback'
        return result

    def _build_result(self, issues):
        errors = sum(1 for i in issues if i['severity'] == 'High')
        return {'issues': issues, 'summary': {'total': len(issues), 'errors': errors, 'warnings': len(issues) - errors}}
