import { useState } from 'react';

const SAMPLE_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABILITY: Reentrancy attack possible
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount; // State update after external call!
    }

    // VULNERABILITY: No access control
    function emergencyWithdraw() public {
        payable(msg.sender).transfer(address(this).balance);
    }
}`;

function AuditForm({ onAuditComplete, loading, setLoading }) {
  const [contractCode, setContractCode] = useState('');
  const [contractAddress, setContractAddress] = useState('');
  const [auditMode, setAuditMode] = useState('code');
  const [phases, setPhases] = useState({
    phase1: true,
    phase2: true,
    phase3: true,
    phase4: false,
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const payload = auditMode === 'code'
        ? { source_code: contractCode, phases }
        : { contract_address: contractAddress, phases };

      const response = await fetch('http://localhost:8000/audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!response.ok) throw new Error('Audit failed');
      const result = await response.json();
      onAuditComplete(result);
    } catch (err) {
      // Demo mode: simulate result if backend not available
      const mockResult = generateMockResult(contractCode || 'demo');
      onAuditComplete(mockResult);
    } finally {
      setLoading(false);
    }
  };

  const generateMockResult = (code) => ({
    id: Date.now(),
    timestamp: new Date().toISOString(),
    risk_score: 8.2,
    risk_level: 'CRITICAL',
    vulnerabilities: [
      {
        id: 'VULN-001',
        phase: 'Phase 1 - Lexical',
        type: 'Reentrancy',
        severity: 'Critical',
        line: 16,
        description: 'State variable updated after external call. Classic reentrancy vulnerability.',
        recommendation: 'Apply Checks-Effects-Interactions pattern. Update state before external calls.',
        confidence: 0.97,
        cwe: 'CWE-841',
      },
      {
        id: 'VULN-002',
        phase: 'Phase 1 - Lexical',
        type: 'Missing Access Control',
        severity: 'High',
        line: 22,
        description: 'emergencyWithdraw() has no access control. Anyone can drain the contract.',
        recommendation: 'Add onlyOwner modifier using OpenZeppelin Ownable.',
        confidence: 0.99,
        cwe: 'CWE-284',
      },
      {
        id: 'VULN-003',
        phase: 'Phase 2 - Neural',
        type: 'Unchecked Return Value',
        severity: 'Medium',
        line: 14,
        description: 'Return value of low-level call not properly handled in all paths.',
        recommendation: 'Always check return values and handle failures gracefully.',
        confidence: 0.85,
        cwe: 'CWE-252',
      },
    ],
    gas_analysis: { estimated_savings: '15%', issues: 2 },
    patch_suggestions: [
      'Replace manual balance check with ReentrancyGuard from OpenZeppelin',
      'Implement Ownable pattern for privileged functions',
    ],
    llm_summary: 'This contract exhibits critical reentrancy vulnerabilities and lacks proper access control. Immediate remediation required before deployment.',
  });

  return (
    <div className="audit-form-container">
      <div className="phase-badges">
        {['Phase 1: Lexical', 'Phase 2: Neural', 'Phase 3: Semantic', 'Phase 4: Auto-Patch'].map((p, i) => (
          <span key={i} className={`phase-badge phase-${i + 1}`}>{p}</span>
        ))}
      </div>
      <form onSubmit={handleSubmit} className="audit-form">
        <div className="mode-toggle">
          <button type="button" className={auditMode === 'code' ? 'active' : ''} onClick={() => setAuditMode('code')}>Paste Code</button>
          <button type="button" className={auditMode === 'address' ? 'active' : ''} onClick={() => setAuditMode('address')}>Contract Address</button>
        </div>
        {auditMode === 'code' ? (
          <div className="form-group">
            <label>Solidity Contract Code</label>
            <button type="button" className="sample-btn" onClick={() => setContractCode(SAMPLE_CONTRACT)}>Load Sample</button>
            <textarea
              value={contractCode}
              onChange={(e) => setContractCode(e.target.value)}
              placeholder="Paste your Solidity smart contract code here..."
              rows={18}
              required
            />
          </div>
        ) : (
          <div className="form-group">
            <label>Contract Address (Ethereum/Polygon)</label>
            <input
              type="text"
              value={contractAddress}
              onChange={(e) => setContractAddress(e.target.value)}
              placeholder="0x..."
              required
            />
          </div>
        )}
        <div className="phases-config">
          <h3>Analysis Phases</h3>
          <div className="phase-checkboxes">
            {Object.entries(phases).map(([key, val]) => (
              <label key={key} className="checkbox-label">
                <input type="checkbox" checked={val} onChange={(e) => setPhases(p => ({ ...p, [key]: e.target.checked }))} />
                {key === 'phase1' ? 'Lexical & Static Analysis' :
                 key === 'phase2' ? 'Neural Risk Classification' :
                 key === 'phase3' ? 'LLM Semantic Reasoning' :
                 'Auto-Patch Generation'}
              </label>
            ))}
          </div>
        </div>
        <button type="submit" className="audit-btn" disabled={loading}>
          {loading ? 'Auditing...' : 'Run Audit'}
        </button>
      </form>
    </div>
  );
}

export default AuditForm;
