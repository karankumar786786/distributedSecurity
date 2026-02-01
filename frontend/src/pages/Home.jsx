import React, { useState } from 'react';
import { startFidoRegistration } from '../services/api';

const Home = () => {
    const [msg, setMsg] = useState({ text: '', type: '' });

    const log = (text, type = 'info') => setMsg({ text, type });

    const handleFidoRegister = async () => {
        try {
            log('Starting FIDO passkey registration...', 'info');
            await startFidoRegistration();
            log('Passkey registered successfully! You can now use it to login.', 'success');
        } catch (e) {
            log(e.message || 'FIDO setup failed', 'error');
        }
    };

    return (
        <div className="auth-container" style={{ maxWidth: '600px' }}>
            <div className="auth-header">
                <h2>Welcome</h2>
                <p className="text-sm">You are successfully logged in.</p>
            </div>
            
            <div className="animate-fade-in">
                 <div style={{ marginBottom: '2rem', textAlign: 'center' }}>
                     <p>You can manage your account security here.</p>
                 </div>

                 <div style={{ background: 'rgba(255,255,255,0.05)', borderRadius: '1rem', padding: '1.5rem' }}>
                    <h3 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <span>🔐</span> Passkeys
                    </h3>
                    <p className="text-sm" style={{ marginBottom: '1rem', color: '#cbd5e1' }}>
                        Add a passkey to sign in securely without typing a password.
                    </p>
                    <button className="btn" onClick={handleFidoRegister}>Register New Passkey</button>
                 </div>
                 
                 <div style={{ marginTop: '2rem', textAlign: 'center' }}>
                     <a href="/login" style={{ color: '#ef4444', textDecoration: 'none', fontWeight: 'bold' }}>Logout</a>
                 </div>
            </div>

            {msg.text && (
                 <div className={`message ${msg.type}`}>
                    {msg.text}
                </div>
            )}
        </div>
    );
};

export default Home;
