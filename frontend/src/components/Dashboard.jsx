function Dashboard({ history }) {
  const totalAudits = history.length;
  const criticalCount = history.filter(r => r.risk_level === 'CRITICAL').length;
  const avgScore = totalAudits > 0 ? (history.reduce((s, r) => s + r.risk_score, 0) / totalAudits).toFixed(1) : 0;
  const totalVulns = history.reduce((s, r) => s + (r.vulnerabilities?.length || 0), 0);
  const severityStats = ['Critical','High','Medium','Low'].map(sev => ({
    name: sev,
    count: history.reduce((s, r) => s + (r.vulnerabilities?.filter(v => v.severity === sev).length || 0), 0),
  }));
  const maxCount = Math.max(...severityStats.map(s => s.count), 1);
  return (
    <div className="dashboard">
      <h2>Audit Dashboard</h2>
      <div className="stats-grid">
        <div className="stat-card"><div className="stat-value">{totalAudits}</div><div className="stat-label">Total Audits</div></div>
        <div className="stat-card"><div className="stat-value">{avgScore}</div><div className="stat-label">Avg Risk Score</div></div>
        <div className="stat-card critical"><div className="stat-value">{criticalCount}</div><div className="stat-label">Critical Contracts</div></div>
        <div className="stat-card"><div className="stat-value">{totalVulns}</div><div className="stat-label">Total Vulnerabilities</div></div>
      </div>
      <div className="dashboard-charts">
        <div className="chart-card">
          <h3>Severity Distribution</h3>
          {totalAudits === 0 ? <p className="no-data">No audit data yet.</p> : (
            <div className="bar-chart">
              {severityStats.map(({ name, count }) => (
                <div key={name} className="bar-row">
                  <span className="bar-label">{name}</span>
                  <div className="bar-track"><div className={`bar-fill bar-${name.toLowerCase()}`} style={{ width: `${(count/maxCount)*100}%` }} /></div>
                  <span className="bar-count">{count}</span>
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="chart-card">
          <h3>Recent Audits</h3>
          {history.length === 0 ? <p className="no-data">No audits yet.</p> : (
            <div className="history-list">
              {history.slice(0, 10).map(item => (
                <div key={item.id} className="history-item">
                  <span className={`risk-badge risk-${item.risk_level?.toLowerCase()}`}>{item.risk_level}</span>
                  <span>Score: {item.risk_score}/10</span>
                  <span>{item.vulnerabilities?.length || 0} vulns</span>
                  <span className="history-time">{new Date(item.timestamp).toLocaleString()}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
      <div className="phase-overview">
        <h3>Analysis Pipeline</h3>
        <div className="pipeline">
          {[{phase:'Phase 1',name:'Lexical Observer',desc:'AST + Solhint + Slither',icon:'L'},
            {phase:'Phase 2',name:'Neural Auditor',desc:'CFG + CodeBERT',icon:'N'},
            {phase:'Phase 3',name:'Semantic Architect',desc:'LLM Chain-of-Thought',icon:'S'},
            {phase:'Phase 4',name:'Patch Agent',desc:'Auto-Fix + Verification',icon:'P'}]
            .map(({ phase, name, desc, icon }) => (
              <div key={phase} className="pipeline-stage">
                <div className="pipeline-icon">{icon}</div>
                <div className="pipeline-info">
                  <div className="pipeline-phase">{phase}</div>
                  <div className="pipeline-name">{name}</div>
                  <div className="pipeline-desc">{desc}</div>
                </div>
              </div>
            ))}
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
