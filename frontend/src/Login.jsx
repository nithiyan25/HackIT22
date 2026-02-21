import React, { useState } from 'react';
import axios from 'axios';

const Login = ({ onLogin }) => {
    const [accountNumber, setAccountNumber] = useState('');
    const [error, setError] = useState('');
    const [isLoading, setIsLoading] = useState(false);

    const handleLogin = async (e) => {
        e.preventDefault();
        setIsLoading(true);
        setError('');
        try {
            const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
            const response = await axios.post(`${API_URL}/login`, { account_number: accountNumber });

            if (response.data.success) {
                onLogin(response.data.user);
            } else {
                setError(response.data.error || 'Login failed');
            }
        } catch (err) {
            setError('Failed to connect to authentication server. Is the backend running?');
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="login-container">
            <div className="login-card">
                <h1 className="main-title">HackIT Security Lab</h1>
                <p className="subtitle">LLM Firewall Testing Environment</p>

                <form onSubmit={handleLogin} className="login-form">
                    <div className="input-group">
                        <label>Account Number</label>
                        <input
                            type="text"
                            value={accountNumber}
                            onChange={(e) => setAccountNumber(e.target.value.toUpperCase())}
                            placeholder="ACCT-1001"
                            disabled={isLoading}
                            required
                        />
                    </div>
                    {error && <div className="error-message">{error}</div>}
                    <button type="submit" className="login-button" disabled={isLoading}>
                        {isLoading ? "Connecting..." : "Start Session"}
                    </button>
                </form>

                <div className="demo-accounts">
                    <p className="demo-title">Available Test Accounts</p>
                    <ul>
                        <li><code>ACCT-1001</code></li>
                        <li><code>ACCT-1004</code></li>
                    </ul>
                </div>
            </div>
        </div>
    );
};

export default Login;
