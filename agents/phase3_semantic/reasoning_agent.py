# Phase 3: Semantic Architect - LLM Reasoning Agent
# SolGuard AI - Chain-of-Thought vulnerability reasoning with GPT-4/Claude

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Any
import logging

logger = logging.getLogger('ReasoningAgent')
logging.basicConfig(level=logging.INFO)

# Chain-of-Thought prompt template
COT_SYSTEM_PROMPT = """You are a Lead Blockchain Security Researcher specializing in Solidity smart contract audits.
Analyze the provided vulnerability finding and:
1. Explain WHY this pattern is dangerous (attacker perspective)
2. Describe the exact attack vector step by step
3. Assess the real-world impact (ETH loss, state corruption, access bypass)
4. Reference the CWE classification
5. Suggest the OpenZeppelin-based fix

Be precise, technical, and actionable. Use the Checks-Effects-Interactions pattern as a reference."""

USER_PROMPT_TEMPLATE = """Contract: {contract_name}
Vulnerability: {vuln_title}
Severity: {severity} | CWE: {cwe}
Affected Lines: {lines}
Code Context:
```solidity
{code_snippet}
```

Provide a Chain-of-Thought security analysis:"""


class ReasoningAgent:
    """Phase 3 Semantic Architect - LLM-powered CoT reasoning."""

    def __init__(self, llm_provider='openai', output_dir='./output/phase3'):
        self.llm_provider = llm_provider
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.client = self._init_client()

    def _init_client(self):
        try:
            if self.llm_provider == 'openai':
                import openai
                return openai.OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
            elif self.llm_provider == 'anthropic':
                import anthropic
                return anthropic.Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))
        except ImportError:
            logger.warning(f'{self.llm_provider} SDK not installed. Using mock reasoning.')
        return None

    def reason(self, classified_results: Dict, sol_file_path: str = None) -> Dict:
        """Run CoT reasoning on classified findings."""
        findings = classified_results.get('classified_findings', [])
        contract_file = classified_results.get('contract_file', 'unknown')
        contract_name = Path(contract_file).stem

        # Read source code for context
        source_lines = []
        if sol_file_path and Path(sol_file_path).exists():
            source_lines = Path(sol_file_path).read_text().splitlines()

        reasoned = []
        for finding in findings[:10]:  # Limit to top 10 findings
            analysis = self._analyze_finding(finding, contract_name, source_lines)
            reasoned.append({**finding, 'cot_analysis': analysis})

        result = {
            'contract_file': contract_file,
            'contract_name': contract_name,
            'reasoned_findings': reasoned,
            'cross_contract_risks': self._cross_contract_analysis(classified_results),
            'llm_provider': self.llm_provider,
            'phase': 3,
            'agent': 'ReasoningAgent'
        }

        out = self.output_dir / f"{contract_name}_reasoned.json"
        with open(out, 'w') as f:
            json.dump(result, f, indent=2)
        return result

    def _analyze_finding(self, finding: Dict, contract_name: str, source_lines: List[str]) -> Dict:
        """Generate CoT analysis for a single finding."""
        lines = finding.get('lines', [])
        code_snippet = self._get_code_snippet(source_lines, lines)

        prompt = USER_PROMPT_TEMPLATE.format(
            contract_name=contract_name,
            vuln_title=finding.get('title', 'Unknown'),
            severity=finding.get('severity', 'UNKNOWN'),
            cwe=finding.get('cwe', 'CWE-000'),
            lines=str(lines),
            code_snippet=code_snippet or '# Code not available'
        )

        if self.client:
            reasoning = self._llm_reason(prompt)
        else:
            reasoning = self._mock_reason(finding)

        return {
            'reasoning': reasoning,
            'attack_vector': self._extract_attack_vector(finding),
            'impact_analysis': self._impact_analysis(finding),
            'references': self._get_references(finding)
        }

    def _llm_reason(self, prompt: str) -> str:
        """Call LLM API for reasoning."""
        try:
            if self.llm_provider == 'openai':
                resp = self.client.chat.completions.create(
                    model='gpt-4-turbo-preview',
                    messages=[
                        {'role': 'system', 'content': COT_SYSTEM_PROMPT},
                        {'role': 'user', 'content': prompt}
                    ],
                    max_tokens=1000,
                    temperature=0.1
                )
                return resp.choices[0].message.content
            elif self.llm_provider == 'anthropic':
                resp = self.client.messages.create(
                    model='claude-3-5-sonnet-20241022',
                    max_tokens=1000,
                    system=COT_SYSTEM_PROMPT,
                    messages=[{'role': 'user', 'content': prompt}]
                )
                return resp.content[0].text
        except Exception as e:
            logger.error(f'LLM API error: {e}')
            return f'LLM reasoning failed: {str(e)}'

    def _mock_reason(self, finding: Dict) -> str:
        """Mock reasoning for testing without API keys."""
        vuln_id = finding.get('id', 'unknown')
        reasoning_map = {
            'reentrancy-eth': (
                '[CoT Analysis] This external call occurs BEFORE the state variable update. '
                'Step 1: Attacker calls withdraw(). '
                'Step 2: Contract sends ETH via .call{value}(). '
                'Step 3: Attacker fallback() re-enters withdraw() before balance is set to 0. '
                'Step 4: Process repeats until contract is drained. '
                'Fix: Apply nonReentrant modifier from OpenZeppelin ReentrancyGuard. '
                'Move state updates BEFORE external calls (CEI pattern).'
            ),
            'tx-origin': (
                '[CoT Analysis] tx.origin returns the original transaction sender. '
                'Attack: Malicious contract tricks user into calling it. '
                'tx.origin still points to victim, bypassing auth check. '
                'Fix: Replace tx.origin with msg.sender for authorization.'
            ),
            'weak-prng': (
                '[CoT Analysis] block.timestamp/difficulty is miner-controlled. '
                'Attack: Miner can slightly adjust timestamp to influence outcome. '
                'Impact: Predictable lottery/randomness outcomes. '
                'Fix: Use Chainlink VRF for verifiable randomness.'
            ),
        }
        return reasoning_map.get(vuln_id, f'[CoT Analysis] {finding.get("title","")} requires manual review. CWE: {finding.get("cwe","")}')

    def _get_code_snippet(self, source_lines: List[str], line_numbers: List) -> str:
        if not source_lines or not line_numbers:
            return ''
        flat_lines = []
        for ln in line_numbers:
            if isinstance(ln, list):
                flat_lines.extend(ln)
            elif isinstance(ln, int):
                flat_lines.append(ln)
        if not flat_lines:
            return ''
        start = max(0, min(flat_lines) - 3)
        end = min(len(source_lines), max(flat_lines) + 3)
        return '\n'.join(f'{i+1}: {line}' for i, line in enumerate(source_lines[start:end], start))

    def _extract_attack_vector(self, finding: Dict) -> str:
        vectors = {
            'reentrancy-eth': 'External call reentrancy via fallback function',
            'controlled-delegatecall': 'Storage layout collision via delegatecall proxy',
            'suicidal': 'Unauthorized selfdestruct() call to destroy contract',
            'tx-origin': 'Phishing attack exploiting tx.origin authorization',
            'weak-prng': 'Miner timestamp manipulation for predictable outcomes',
        }
        return vectors.get(finding.get('id', ''), 'Direct exploitation of identified vulnerability')

    def _impact_analysis(self, finding: Dict) -> Dict:
        cwe_impacts = {
            'CWE-841': {'funds_at_risk': True, 'severity': 'Total contract drain possible'},
            'CWE-284': {'funds_at_risk': True, 'severity': 'Unauthorized access to privileged functions'},
            'CWE-829': {'funds_at_risk': True, 'severity': 'Complete contract takeover via storage collision'},
            'CWE-338': {'funds_at_risk': False, 'severity': 'Predictable outcomes in gambling/NFT minting'},
            'CWE-190': {'funds_at_risk': True, 'severity': 'Integer overflow allowing balance manipulation'},
        }
        return cwe_impacts.get(finding.get('cwe', ''), {'funds_at_risk': False, 'severity': 'Moderate risk'})

    def _get_references(self, finding: Dict) -> List[str]:
        return [
            f'https://swcregistry.io/docs/SWC-{finding.get("cwe","").replace("CWE-","")}',
            'https://docs.openzeppelin.com/contracts/4.x/api/security',
            'https://consensys.github.io/smart-contract-best-practices/'
        ]

    def _cross_contract_analysis(self, results: Dict) -> Dict:
        findings = results.get('classified_findings', [])
        proxy_risks = any(f.get('id') == 'controlled-delegatecall' for f in findings)
        reentrancy_risks = any(f.get('id') in ['reentrancy-eth', 'reentrancy-no-eth'] for f in findings)
        return {
            'proxy_pattern_risks': proxy_risks,
            'cross_contract_reentrancy': reentrancy_risks,
            'recommendation': 'Enable cross-file analysis for proxy contract verification' if proxy_risks else 'No proxy patterns detected'
        }


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python reasoning_agent.py <classified_results.json> [contract.sol]')
        sys.exit(1)
    with open(sys.argv[1]) as f:
        data = json.load(f)
    sol_file = sys.argv[2] if len(sys.argv) > 2 else None
    agent = ReasoningAgent(llm_provider=os.getenv('LLM_PROVIDER', 'openai'))
    result = agent.reason(data, sol_file)
    print(f'[SolGuard AI] Phase 3: Semantic Analysis Complete')
    print(f'[+] {len(result["reasoned_findings"])} findings analyzed with CoT reasoning')
    for f in result['reasoned_findings'][:3]:
        print(f'\n[{f["risk_label"]}] {f["title"]}')
        cot = f.get('cot_analysis', {})
        print(f'  CoT: {str(cot.get("reasoning",""))[:200]}...')
