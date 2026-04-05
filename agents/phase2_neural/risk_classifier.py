# Phase 2: Neural Auditor - Risk Classification Agent
# SolGuard AI - CodeBERT-based vulnerability risk scoring

import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Tuple
import logging

logger = logging.getLogger('RiskClassifier')
logging.basicConfig(level=logging.INFO)

RISK_WEIGHTS = {
    'severity': {'HIGH': 0.5, 'MEDIUM': 0.3, 'LOW': 0.1},
    'confidence': {'High': 1.0, 'Medium': 0.7, 'Low': 0.4},
    'cwe_critical': {
        'CWE-841': 0.9, 'CWE-829': 0.85, 'CWE-284': 0.8,
        'CWE-190': 0.75, 'CWE-338': 0.7, 'CWE-457': 0.65,
    }
}


class RiskClassificationAgent:
    """Phase 2 Neural Auditor using CodeBERT + CFG amplification."""

    def __init__(self, model_path=None, output_dir='./output/phase2'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.model_path = model_path
        self.model_available = self._load_model()

    def _load_model(self):
        try:
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            import torch
            name = self.model_path or 'microsoft/codebert-base'
            self.tokenizer = AutoTokenizer.from_pretrained(name)
            self.model = AutoModelForSequenceClassification.from_pretrained(name, num_labels=3)
            self.model.eval()
            return True
        except Exception:
            return False

    def classify(self, static_results: Dict, ast_data: Dict = None) -> Dict:
        """Classify all findings from Phase 1 with risk scores."""
        findings = static_results.get('static_findings', [])
        contract_file = static_results.get('contract_file', 'unknown')
        classified = [self._score_finding(f, ast_data) for f in findings]
        classified.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
        overall = self._overall_risk(classified)
        result = {
            'contract_file': contract_file,
            'classified_findings': classified,
            'overall_risk': overall,
            'risk_distribution': {
                'critical': sum(1 for f in classified if f['risk_score'] >= 0.8),
                'high': sum(1 for f in classified if 0.6 <= f['risk_score'] < 0.8),
                'medium': sum(1 for f in classified if 0.3 <= f['risk_score'] < 0.6),
                'low': sum(1 for f in classified if f['risk_score'] < 0.3),
            },
            'model_used': 'codebert' if self.model_available else 'rule_based',
            'phase': 2, 'agent': 'RiskClassificationAgent'
        }
        out = self.output_dir / f"{Path(contract_file).stem}_classified.json"
        with open(out, 'w') as fp:
            json.dump(result, fp, indent=2)
        return result

    def _score_finding(self, finding: Dict, ast_data=None) -> Dict:
        if self.model_available:
            score, conf = self._codebert_score(finding)
        else:
            score, conf = self._rule_score(finding)
        if ast_data:
            score = self._cfg_amplify(score, finding, ast_data)
        return {
            **finding,
            'risk_score': round(score, 3),
            'confidence_score': round(conf, 3),
            'risk_label': self._label(score),
            'exploitability': 'HIGH' if finding.get('id') in ['reentrancy-eth','controlled-delegatecall'] else 'MEDIUM',
            'impact': 'CRITICAL' if finding.get('cwe') in ['CWE-841','CWE-829','CWE-284'] else 'HIGH',
            'remediation_priority': 1 if score >= 0.8 else (2 if score >= 0.6 else (3 if score >= 0.3 else 4))
        }

    def _codebert_score(self, finding: Dict):
        import torch
        text = f"{finding.get('title','')} {finding.get('cwe','')}"
        inputs = self.tokenizer(text, return_tensors='pt', truncation=True, max_length=128)
        with torch.no_grad():
            logits = self.model(**inputs).logits
            probs = torch.softmax(logits, dim=-1)[0]
        score = probs[2].item() * 0.9 + probs[1].item() * 0.5 + probs[0].item() * 0.1
        return score, float(probs.max().item())

    def _rule_score(self, finding: Dict):
        base = RISK_WEIGHTS['severity'].get(finding.get('severity', 'LOW'), 0.1)
        conf = RISK_WEIGHTS['confidence'].get(finding.get('confidence', 'Medium'), 0.7)
        cwe = RISK_WEIGHTS['cwe_critical'].get(finding.get('cwe', ''), 0.5)
        return min(1.0, base * 0.4 + cwe * 0.4 + conf * 0.2), conf

    def _cfg_amplify(self, score, finding, ast_data):
        flow = ast_data.get('logic_flow', {})
        if finding.get('id') in ['reentrancy-eth'] and flow.get('external_calls') and flow.get('value_transfers'):
            score = min(1.0, score * 1.25)
        return score

    def _label(self, score):
        return 'CRITICAL' if score >= 0.8 else ('HIGH' if score >= 0.6 else ('MEDIUM' if score >= 0.3 else 'LOW'))

    def _overall_risk(self, classified):
        if not classified:
            return {'score': 0.0, 'label': 'SAFE', 'grade': 'A'}
        mx = max(f['risk_score'] for f in classified)
        avg = sum(f['risk_score'] for f in classified) / len(classified)
        ws = mx * 0.7 + avg * 0.3
        grade = 'F' if ws >= 0.8 else ('D' if ws >= 0.6 else ('C' if ws >= 0.4 else ('B' if ws >= 0.2 else 'A')))
        return {'score': round(ws, 3), 'max': round(mx, 3), 'avg': round(avg, 3), 'label': self._label(ws), 'grade': grade}


if __name__ == '__main__':
    with open(sys.argv[1]) as f:
        data = json.load(f)
    agent = RiskClassificationAgent()
    result = agent.classify(data)
    r = result['overall_risk']
    print(f'[SolGuard AI] Phase 2 | Overall: {r["label"]} Score:{r["score"]} Grade:{r["grade"]}')
    for f in result['classified_findings'][:5]:
        print(f'  [{f["risk_label"]}] {f["title"]} Score:{f["risk_score"]} Confidence:{f["confidence_score"]}')
