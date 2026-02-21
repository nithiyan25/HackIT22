import React, { useState } from 'react';
import axios from 'axios';
import Login from './Login';
import './index.css';

function App() {
  const [user, setUser] = useState(null);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [vulnResponse, setVulnResponse] = useState('');
  const [protResponse, setProtResponse] = useState('');

  const handleSend = async () => {
    if (!input || !user) return;
    setLoading(true);
    setVulnResponse(''); setProtResponse('');

    try {
      const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
      const payload = { message: input, customer_id: user.customer_id };
      const [vulnRes, protRes] = await Promise.all([
        axios.post(`${API_URL}/chat-vulnerable`, payload),
        axios.post(`${API_URL}/chat-protected`, payload)
      ]);
      setVulnResponse(vulnRes.data.response);
      setProtResponse(protRes.data.response);
    } catch (error) {
      setVulnResponse("Error connecting to backend.");
      setProtResponse("Error connecting to backend.");
    }
    setLoading(false);
  };

  if (!user) {
    return <Login onLogin={setUser} />;
  }

  return (
    <div className="container">
      <header>
        <div className="header-top">
          <h1>LLM Attack & Defense Dashboard for a simple Banking System</h1>
          <button className="logout-button" onClick={() => setUser(null)}>End Session</button>
        </div>
        <p>Authenticated as: <strong>{user.name} (Customer ID: {user.customer_id})</strong></p>
      </header>

      <div className="input-section">
        <textarea rows="3" placeholder="Enter prompt injection here..." value={input} onChange={(e) => setInput(e.target.value)} />
        <button onClick={handleSend} disabled={loading}>{loading ? 'Processing...' : 'Send Request'}</button>
      </div>

      <div className="panels">
        <div className="panel normal-panel">
          <h2>🔴 Vulnerable Pipeline</h2>
          <div className="response-box text-blue">{vulnResponse || "Awaiting input..."}</div>
        </div>
        <div className="panel protected-panel">
          <h2>🟢 Protected Pipeline</h2>
          <div className="response-box text-green">{protResponse || "Awaiting input..."}</div>
        </div>
      </div>
    </div>
  );
}

export default App;