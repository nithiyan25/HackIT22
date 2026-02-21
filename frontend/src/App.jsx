import React, { useState } from 'react';
import axios from 'axios';
import './index.css';

function App() {
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [vulnResponse, setVulnResponse] = useState('');
  const [protResponse, setProtResponse] = useState('');

  const handleSend = async () => {
    if (!input) return;
    setLoading(true);
    setVulnResponse(''); setProtResponse('');

    try {
      const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
      const [vulnRes, protRes] = await Promise.all([
        axios.post(`${API_URL}/chat-normal`, { message: input }),
        axios.post(`${API_URL}/chat-protected`, { message: input })
      ]);
      setVulnResponse(vulnRes.data.response);
      setProtResponse(protRes.data.response);
    } catch (error) {
      setVulnResponse("Error connecting to backend.");
      setProtResponse("Error connecting to backend.");
    }
    setLoading(false);
  };

  return (
    <div className="container">
      <header>
        <h1>LLM Attack & Defense Dashboard</h1>
        <p>Authenticated as: <strong>Alice (Customer ID: 1)</strong></p>
      </header>

      <div className="input-section">
        <textarea rows="3" placeholder="Enter prompt injection here..." value={input} onChange={(e) => setInput(e.target.value)} />
        <button onClick={handleSend} disabled={loading}>{loading ? 'Processing...' : 'Send Request'}</button>
      </div>

      <div className="panels">
        <div className="panel normal-panel">
          <h2>⚪ Normal LLM Pipeline</h2>
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