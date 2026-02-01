import React, { useState, useEffect } from 'react';
import { checkUser, initPasswordLogin, completePasswordLogin, initFidoLogin, completeFidoLogin } from '../services/api';
import { useNavigate, useSearchParams } from 'react-router-dom';

const Login = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [step, setStep] = useState(1); // 1: Check User, 2: Select Method
    const [method, setMethod] = useState(null); // 'password' or 'fido'
    const [msg, setMsg] = useState({ text: '', type: '' });
    const [availableMethods, setAvailableMethods] = useState({ password: true, fido: false });
    
    const navigate = useNavigate();
    const [searchParams] = useSearchParams();
    const returnTo = searchParams.get('return_to');
    const paramUsername = searchParams.get('username');

    useEffect(() => {
        if (paramUsername) {
            setUsername(paramUsername);
        }
    }, [paramUsername]);

    const log = (text, type = 'info') => setMsg({ text, type });

    const handleSuccess = () => {
        log('Redirecting...', 'success');
        setTimeout(() => {
            if (returnTo) {
                window.location.href = returnTo;
            } else {
                navigate('/'); // Redirect to Home
            }
        }, 1000);
    };

    const handleCheckUser = async () => {
        try {
            log('Checking user...');
            const data = await checkUser(username);
            if (data.exist) {
                log('User found! Choose login method.', 'success');
                // Backend keys identified from CoreAuthenticationService.java:
                // "passwordLoginAvailable" -> boolean
                // "passKeyLoginAvailable" -> boolean
                log(`Login methods found: ${JSON.stringify(data.data)}`, 'info');
                setAvailableMethods(data.data || { passwordLoginAvailable: true, passKeyLoginAvailable: false }); 
                setStep(2);
            } else {
                log('User not found.', 'error');
            }
        } catch (e) {
            log(e.message || 'Error checking user', 'error');
        }
    };

    const handlePasswordLogin = async () => {
        try {
            log('Initializing Password Login...');
            await initPasswordLogin();
            log('Completing Password Login...');
            await completePasswordLogin(password);
            log('Login Successful!', 'success');
            handleSuccess();
        } catch (e) {
            log(e.message || 'Login failed', 'error');
        }
    };

    const handleFidoLogin = async () => {
        try {
            log('Initializing FIDO Login...');
            const data = await initFidoLogin();
            log('Please touch your security key...', 'info');
            await completeFidoLogin(data.options);
            log('FIDO Login Successful!', 'success');
            handleSuccess();
        } catch (e) {
            log(e.message || 'FIDO Login failed', 'error');
        }
    };

    return (
        <div className="auth-container">
            <div className="auth-header">
                <h2>Welcome Back</h2>
                <p className="text-sm">Sign in to access your dashboard</p>
            </div>
            
            {step === 1 && (
                <div className="animate-fade-in">
                    <div className="form-group">
                        <input 
                            className="form-control"
                            type="text" 
                            placeholder="Username" 
                            value={username} 
                            onChange={e => setUsername(e.target.value)} 
                        />
                    </div>
                    <button className="btn" onClick={handleCheckUser}>Check User</button>
                    <div className="text-center" style={{ marginTop: '1rem' }}>
                        <span className="text-sm">Need an account? </span>
                        <a href={returnTo ? `/register?return_to=${encodeURIComponent(returnTo)}` : "/register"}>Register here</a>
                    </div>
                </div>
            )}

            {step === 2 && !method && (
                <div className="animate-fade-in">
                     <div className="text-center" style={{ marginBottom: '1.5rem' }}>
                        <p className="text-sm">Hello,</p>
                        <h3>{username}</h3>
                    </div>
                    
                    {/* Dynamic Buttons based on availableMethods */}
                    {availableMethods.passwordLoginAvailable && (
                        <button className="btn" onClick={() => setMethod('password')}>Password Login</button>
                    )}
                    
                    {availableMethods.passKeyLoginAvailable && (
                        <button className="btn btn-secondary" onClick={() => { setMethod('fido'); handleFidoLogin(); }}>FIDO Login</button>
                    )}

                    <button className="btn btn-outline" onClick={() => setStep(1)} style={{ marginTop: '0.5rem' }}>Back to Username</button>
                </div>
            )}

            {step === 2 && method === 'password' && (
                <div className="animate-fade-in">
                    <div className="form-group">
                        <input 
                            className="form-control"
                            type="password" 
                            placeholder="Password" 
                            value={password} 
                            onChange={e => setPassword(e.target.value)} 
                        />
                    </div>
                    <button className="btn" onClick={handlePasswordLogin}>Login</button>
                    <button className="btn btn-outline" onClick={() => setMethod(null)} style={{ marginTop: '0.5rem' }}>Back to Methods</button>
                </div>
            )}

            {step === 2 && method === 'fido' && (
                <div className="text-center animate-fade-in">
                    <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🔐</div>
                    <p style={{ marginBottom: '1.5rem' }}>Please touch your security key to continue.</p>
                    <button className="btn btn-outline" onClick={() => setMethod(null)}>Cancel</button>
                </div>
            )}

            {msg.text && (
                <div className={`message ${msg.type}`}>
                    {msg.text}
                </div>
            )}
        </div>
    );
};

export default Login;
