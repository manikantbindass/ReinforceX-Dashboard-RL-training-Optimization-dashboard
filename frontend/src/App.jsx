import { useState } from 'react';
import AuditForm from './components/AuditForm';
import AuditReport from './components/AuditReport';
import Dashboard from './components/Dashboard';
import './App.css';

function App() {
  const [activeTab, setActiveTab] = useState('audit');
  const [auditResult, setAuditResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState([]);

  const handleAuditComplete = (result) => {
    setAuditResult(result);
    setHistory(prev => [result, ...prev].slice(0, 20));
    setActiveTab('report');
  };

  return (
    <div className="app">
      <header className="app-header">
        <div className="logo">
          <span className="logo-icon">🛡️</span>
          <h1>SolGuard AI</h1>
          <span className="tagline">Autonomous Smart Contract Auditor</span>
        </div>
        <nav className="nav-tabs">
          <button
            className={activeTab === 'audit' ? 'active' : ''}
            onClick={() => setActiveTab('audit')}
          >Audit</button>
          <button
            className={activeTab === 'report' ? 'active' : ''}
            onClick={() => setActiveTab('report')}
            disabled={!auditResult}
          >Report</button>
          <button
            className={activeTab === 'dashboard' ? 'active' : ''}
            onClick={() => setActiveTab('dashboard')}
          >Dashboard</button>
        </nav>
      </header>
      <main className="app-main">
        {activeTab === 'audit' && (
          <AuditForm
            onAuditComplete={handleAuditComplete}
            loading={loading}
            setLoading={setLoading}
          />
        )}
        {activeTab === 'report' && auditResult && (
          <AuditReport result={auditResult} />
        )}
        {activeTab === 'dashboard' && (
          <Dashboard history={history} />
        )}
      </main>
    </div>
  );
}

export default App;
