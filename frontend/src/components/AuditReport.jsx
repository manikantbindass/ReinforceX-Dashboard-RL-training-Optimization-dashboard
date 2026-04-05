function SeverityBadge({ severity }) {
  const colors = { Critical: '#ff4444', High: '#ff8800', Medium: '#ffcc00', Low: '#44bb44', Info: '#4488ff' };
  return <span style={{ background: colors[severity] || '#888', color: '#fff', padding: '2px 8px', borderRadius: '12px', fontSize: '12px', fontWeight: 'bold' }}>{severity}</span>;
}

function AuditReport({ result }) {
  if (!result) return null;
  const severityOrder = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  const sorted = [...result.vulnerabilities].sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5));
  const riskColor = result.risk_score >= 8 ? '#ff4444' : result.risk_score >= 5 ? '#ff8800' : '#44bb44';
  return (
    <div className="audit-report">
      <div className="report-header">
        <div className="risk-score" style={{ borderColor: riskColor }}>
          <span className="score-value" style={{ color: riskColor }}>{result.risk_score}</span>
          <span className="score-label"> / 10</span>
          <div className="risk-level" style={{ color: riskColor }}>{result.risk_level}</div>
        </div>
        <div className="report-meta">
          <h2>Audit Report</h2>
          <p>{new Date(result.timestamp).toLocaleString()}</p>
          <div className="vuln-counts">
            {['Critical','High','Medium','Low'].map(sev => {
              const count = result.vulnerabilities.filter(v => v.severity === sev).length;
              return count > 0 ? <span key={sev} className="vuln-count"><SeverityBadge severity={sev} /> {count}</span> : null;
            })}
          </div>
        </div>
      </div>
      {result.llm_summary && <div className="llm-summary"><h3>AI Summary</h3><p>{result.llm_summary}</p></div>}
      <div className="vulnerabilities-list">
        <h3>Vulnerabilities ({result.vulnerabilities.length})</h3>
        {sorted.map(vuln => (
          <div key={vuln.id} className="vuln-card">
            <div className="vuln-header">
              <SeverityBadge severity={vuln.severity} />
              <strong>{vuln.type}</strong>
              <span className="vuln-id">{vuln.id}</span>
              {vuln.line && <span>Line {vuln.line}</span>}
              {vuln.cwe && <span>{vuln.cwe}</span>}
              <span className="phase-tag">{vuln.phase}</span>
            </div>
            <p>{vuln.description}</p>
            <p><strong>Fix:</strong> {vuln.recommendation}</p>
            {vuln.confidence && <p>Confidence: {Math.round(vuln.confidence * 100)}%</p>}
          </div>
        ))}
      </div>
      {result.patch_suggestions?.length > 0 && (
        <div className="patch-suggestions">
          <h3>Auto-Patch Suggestions</h3>
          <ul>{result.patch_suggestions.map((p, i) => <li key={i}>{p}</li>)}</ul>
        </div>
      )}
      {result.gas_analysis && (
        <div className="gas-analysis">
          <h3>Gas Analysis</h3>
          <p>Estimated savings: <strong>{result.gas_analysis.estimated_savings}</strong> | Issues: <strong>{result.gas_analysis.issues}</strong></p>
        </div>
      )}
    </div>
  );
}

export default AuditReport;
