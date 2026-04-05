"""
Phase 1: Lexical Observer - Parsing Agent
SolGuard AI - Autonomous Smart Contract Auditing Platform

Converts raw Solidity source code into Abstract Syntax Trees (AST)
and produces a structured JSON representation of contract logic flow.
"""

import json
import subprocess
import sys
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ParsingAgent')


class ParsingAgent:
    """
    Phase 1 Parsing Agent
    Converts Solidity source code into AST and structured JSON.
    Integrates with solc compiler for AST generation.
    """

    def __init__(self, solc_path: str = 'solc', output_dir: str = './output/phase1'):
        self.solc_path = solc_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f'ParsingAgent initialized. Output dir: {self.output_dir}')

    def parse_contract(self, sol_file_path: str) -> Dict[str, Any]:
        """
        Main entry point: parse a Solidity file into structured JSON.
        Returns AST + metadata.
        """
        sol_path = Path(sol_file_path)
        if not sol_path.exists():
            raise FileNotFoundError(f'Contract file not found: {sol_file_path}')

        logger.info(f'Parsing contract: {sol_path.name}')

        # Generate AST using solc
        ast_data = self._generate_ast(sol_path)

        # Extract contract metadata
        metadata = self._extract_metadata(sol_path, ast_data)

        # Build logic flow graph
        logic_flow = self._build_logic_flow(ast_data)

        result = {
            'contract_file': str(sol_path),
            'contract_name': metadata.get('name', 'Unknown'),
            'solidity_version': metadata.get('version', 'unknown'),
            'ast_nodes': metadata.get('node_count', 0),
            'functions': metadata.get('functions', []),
            'state_variables': metadata.get('state_variables', []),
            'events': metadata.get('events', []),
            'modifiers': metadata.get('modifiers', []),
            'inheritance': metadata.get('inheritance', []),
            'logic_flow': logic_flow,
            'raw_ast': ast_data,
            'phase': 1,
            'agent': 'ParsingAgent'
        }

        # Save output
        output_file = self.output_dir / f"{sol_path.stem}_ast.json"
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
        logger.info(f'AST saved to: {output_file}')

        return result

    def _generate_ast(self, sol_path: Path) -> Dict:
        """Run solc compiler to generate AST JSON."""
        try:
            cmd = [
                self.solc_path,
                '--ast-compact-json',
                '--allow-paths', '.',
                str(sol_path)
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                logger.warning(f'solc warning/error: {result.stderr[:500]}')
                # Return fallback AST from source parsing
                return self._fallback_parse(sol_path)

            # Parse AST JSON from solc output
            ast_lines = result.stdout.split('\n')
            ast_json_str = ''
            capture = False
            for line in ast_lines:
                if line.startswith('{'):
                    capture = True
                if capture:
                    ast_json_str += line + '\n'

            if ast_json_str.strip():
                return json.loads(ast_json_str)
            return self._fallback_parse(sol_path)

        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning('solc not available, using fallback parser')
            return self._fallback_parse(sol_path)

    def _fallback_parse(self, sol_path: Path) -> Dict:
        """Fallback: parse Solidity using regex/text analysis when solc is unavailable."""
        import re
        source = sol_path.read_text()

        functions = re.findall(r'function\s+(\w+)\s*\(([^)]*)\)', source)
        state_vars = re.findall(r'^\s*(\w+(?:\s+\w+)*)\s+(?:public|private|internal|external)?\s*(\w+)\s*;', source, re.MULTILINE)
        events = re.findall(r'event\s+(\w+)\s*\(', source)
        modifiers = re.findall(r'modifier\s+(\w+)\s*\(', source)
        contracts = re.findall(r'contract\s+(\w+)', source)
        pragmas = re.findall(r'pragma\s+solidity\s+([^;]+);', source)

        return {
            'nodeType': 'SourceUnit',
            'fallback': True,
            'contracts': contracts,
            'functions': [{'name': f[0], 'params': f[1]} for f in functions],
            'state_variables': state_vars,
            'events': events,
            'modifiers': modifiers,
            'pragma': pragmas[0] if pragmas else 'unknown',
            'line_count': len(source.splitlines()),
            'char_count': len(source)
        }

    def _extract_metadata(self, sol_path: Path, ast_data: Dict) -> Dict:
        """Extract high-level metadata from AST."""
        source = sol_path.read_text()
        import re

        name_match = re.search(r'contract\s+(\w+)', source)
        pragma_match = re.search(r'pragma\s+solidity\s+([^;]+);', source)
        functions = re.findall(r'function\s+(\w+)', source)
        state_vars = re.findall(r'^\s+(?:uint|int|address|bool|bytes|string|mapping)\w*\s+(?:public\s+|private\s+|internal\s+)?(\w+)\s*;', source, re.MULTILINE)
        events = re.findall(r'event\s+(\w+)', source)
        modifiers = re.findall(r'modifier\s+(\w+)', source)
        inheritance = re.findall(r'contract\s+\w+\s+is\s+([\w,\s]+)\s*{', source)

        # Count AST nodes
        ast_str = json.dumps(ast_data)
        node_count = ast_str.count('"nodeType"')

        return {
            'name': name_match.group(1) if name_match else sol_path.stem,
            'version': pragma_match.group(1).strip() if pragma_match else 'unknown',
            'functions': functions,
            'state_variables': state_vars,
            'events': events,
            'modifiers': modifiers,
            'inheritance': inheritance,
            'node_count': max(node_count, len(functions) * 3)
        }

    def _build_logic_flow(self, ast_data: Dict) -> Dict:
        """Build a simplified logic flow representation from AST."""
        return {
            'entry_points': self._find_entry_points(ast_data),
            'state_mutations': self._find_state_mutations(ast_data),
            'external_calls': self._find_external_calls(ast_data),
            'value_transfers': self._find_value_transfers(ast_data)
        }

    def _find_entry_points(self, ast_data: Dict) -> List[str]:
        """Identify public/external functions as entry points."""
        import re
        ast_str = json.dumps(ast_data)
        # Find public and external functions
        pattern = r'"visibility":\s*"(public|external)".*?"name":\s*"(\w+)"'
        matches = re.findall(pattern, ast_str)
        return [m[1] for m in matches] if matches else ['constructor', 'fallback']

    def _find_state_mutations(self, ast_data: Dict) -> List[str]:
        """Find state variable assignments (potential vulnerability sites)."""
        import re
        ast_str = json.dumps(ast_data)
        pattern = r'"nodeType":\s*"Assignment"'
        count = len(re.findall(pattern, ast_str))
        return [f'assignment_node_{i}' for i in range(count)]

    def _find_external_calls(self, ast_data: Dict) -> List[Dict]:
        """Detect external contract calls and low-level calls."""
        import re
        ast_str = json.dumps(ast_data)
        calls = []
        # Low-level calls
        for pattern in [r'\.call\b', r'\.delegatecall\b', r'\.staticcall\b', r'\.transfer\b', r'\.send\b']:
            matches = re.findall(pattern, ast_str)
            if matches:
                calls.append({'type': pattern.strip('\\b.'), 'count': len(matches)})
        return calls

    def _find_value_transfers(self, ast_data: Dict) -> List[str]:
        """Identify ETH value transfer patterns."""
        import re
        ast_str = json.dumps(ast_data)
        transfers = []
        patterns = ['msg.value', 'payable', '.transfer(', '.send(']
        for p in patterns:
            if p in ast_str:
                transfers.append(p)
        return transfers


def parse_contract_file(sol_file: str, output_dir: str = './output/phase1') -> Dict:
    """Convenience function to parse a single contract file."""
    agent = ParsingAgent(output_dir=output_dir)
    return agent.parse_contract(sol_file)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python parsing_agent.py <path_to_contract.sol>')
        sys.exit(1)

    sol_file = sys.argv[1]
    print(f'\n[SolGuard AI] Phase 1: Lexical Observer - Parsing Agent')
    print(f'[*] Analyzing: {sol_file}')

    result = parse_contract_file(sol_file)

    print(f'\n[+] Contract: {result["contract_name"]}')
    print(f'[+] AST Nodes: {result["ast_nodes"]}')
    print(f'[+] Functions: {len(result["functions"])}')
    print(f'[+] State Variables: {len(result["state_variables"])}')
    print(f'[+] External Calls: {len(result["logic_flow"]["external_calls"])}')
    print(f'\n[*] Full AST saved to output/phase1/')
