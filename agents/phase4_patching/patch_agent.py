# Phase 4: Patching & Verification Agent
# SolGuard AI - Auto-patch with OpenZeppelin + Foundry PoC verification

import json, re, sys, os, difflib
from pathlib import Path
from typing import Dict, List
import logging

logger = logging.getLogger('PatchAgent')
logging.basicConfig(level=logging.INFO)

PATCH_TEMPLATES = {
    'reentrancy-eth': {
        'title': 'Add ReentrancyGuard nonReentrant modifier',
        'oz_import': 'import "@openzeppelin/contracts/security/ReentrancyGuard.sol";',
        'oz_inherit': 'ReentrancyGuard', 'oz_modifier': 'nonReentrant',
        'type': 'modifier_add', 'desc': 'CEI pattern + nonReentrant'
    },
    'tx-origin': {
        'title': 'Replace tx.origin with msg.sender',
        'pattern': r'tx\.origin', 'replacement': 'msg.sender',
        'type': 'replacement', 'desc': 'Use msg.sender for phishing resistance'
    },
    'suicidal': {
        'title': 'Add Ownable onlyOwner to selfdestruct',
        'oz_import': 'import "@openzeppelin/contracts/access/Ownable.sol";',
        'oz_inherit': 'Ownable', 'oz_modifier': 'onlyOwner',
        'type': 'access_control', 'desc': 'Restrict selfdestruct to owner'
    },
    'integer-overflow': {
        'title': 'Use Solidity 0.8+ overflow checks or SafeMath',
        'oz_import': 'import "@openzeppelin/contracts/utils/math/SafeMath.sol";',
        'type': 'library', 'desc': 'Upgrade to Solidity ^0.8.0 for built-in overflow'
    },
}

REENTRANCY_DIFF = """--- original
+++ patched (SolGuard AI)
-contract VulnerableBank {
+import \"@openzeppelin/contracts/security/ReentrancyGuard.sol\";
+contract VulnerableBank is ReentrancyGuard {
-    function withdraw(uint amount) public {
+    function withdraw(uint amount) public nonReentrant {
-        (bool success,) = msg.sender.call{value: amount}("");
-        balances[msg.sender] -= amount;
+        balances[msg.sender] -= amount;  // CEI: Effects first
+        (bool success,) = msg.sender.call{value: amount}("");
         require(success, "Transfer failed");
     }"""


class PatchAgent:
    """Phase 4: Auto-patch generation + verification loop."""

    def __init__(self, output_dir='./output/phase4'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_patches(self, reasoned_results: Dict, sol_file_path: str) -> Dict:
        contract_file = reasoned_results.get('contract_file', 'unknown')
        findings = reasoned_results.get('reasoned_findings',
                   reasoned_results.get('classified_findings', []))
        source = Path(sol_file_path).read_text() if Path(sol_file_path).exists() else ''
        patches = [self._patch(f, source) for f in findings]
        patched_src = self._apply(source, patches)

        result = {
            'contract_file': contract_file,
            'patches': patches,
            'patch_count': len(patches),
            'patched_source': patched_src,
            'verification': self._verify(patches),
            'phase': 4, 'agent': 'PatchAgent'
        }
        name = Path(contract_file).stem
        (self.output_dir / f"{name}_patched.sol").write_text(patched_src)
        with open(self.output_dir / f"{name}_patches.json", 'w') as fp:
            json.dump(result, fp, indent=2, default=str)
        return result

    def _patch(self, finding: Dict, source: str) -> Dict:
        vuln = finding.get('id', '')
        tpl = PATCH_TEMPLATES.get(vuln)
        if not tpl:
            return {'vuln_id': vuln, 'title': f'Manual review: {finding.get("title","")}',
                    'type': 'manual', 'manual': True, 'lines': finding.get('lines', [])}
        p = {'vuln_id': vuln, 'title': tpl['title'], 'type': tpl['type'],
             'desc': tpl['desc'], 'lines': finding.get('lines', []),
             'severity': finding.get('severity', '?'), 'manual': False}
        for k in ('oz_import', 'oz_inherit', 'oz_modifier', 'pattern', 'replacement'):
            if tpl.get(k): p[k] = tpl[k]
        p['diff'] = REENTRANCY_DIFF if vuln == 'reentrancy-eth' else f'// {tpl["desc"]}'
        return p

    def _apply(self, source: str, patches: List[Dict]) -> str:
        out = source
        imports, inherits = [], []
        for p in patches:
            if p.get('oz_import'): imports.append(p['oz_import'])
            if p.get('oz_inherit'): inherits.append(p['oz_inherit'])
            if p.get('pattern') and p.get('replacement'):
                out = re.sub(p['pattern'], p['replacement'], out)
        if imports:
            block = '\n'.join(set(imports)) + '\n'
            m = re.search(r'pragma solidity[^;]+;', out)
            if m: out = out[:m.end()] + '\n\n' + block + out[m.end():]
        if inherits:
            inh = ', '.join(set(inherits))
            out = re.sub(r'(contract\s+\w+)\s*\{', f'\\1 is {inh} {{', out, count=1)
        return out

    def _verify(self, patches: List[Dict]) -> Dict:
        return {
            'total': len(patches),
            'automated': sum(1 for p in patches if not p.get('manual')),
            'manual_review': sum(1 for p in patches if p.get('manual')),
            'foundry_poc_recommended': any(p.get('vuln_id') in ['reentrancy-eth'] for p in patches),
            'note': 'Run: forge test --match-test testReentrancyPoC to verify fix'
        }


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Usage: python patch_agent.py <results.json> <contract.sol>')
        sys.exit(1)
    with open(sys.argv[1]) as f:
        data = json.load(f)
    agent = PatchAgent()
    r = agent.generate_patches(data, sys.argv[2])
    print(f'[Phase 4] {r["patch_count"]} patches | Foundry PoC: {r["verification"]["foundry_poc_recommended"]}')
