import React, { useState } from 'react';
import { registerUser } from '../services/api';
import { useSearchParams } from 'react-router-dom';

const Register = () => {
    const [form, setForm] = useState({ username: '', password: '', phoneNumber: '' });
    const [step, setStep] = useState(1); // 1: Register, 2: FIDO Setup
    const [msg, setMsg] = useState({ text: '', type: '' });
    const [searchParams] = useSearchParams();
    const returnTo = searchParams.get('return_to');

    const log = (text, type = 'info') => setMsg({ text, type });

    const handleChange = (e) => setForm({ ...form, [e.target.name]: e.target.value });

    const handleSuccess = () => {
        if (returnTo) {
            log('Redirecting...', 'success');
            setTimeout(() => {
                window.location.href = returnTo;
            }, 1000);
        } else {
             window.location.href = '/login';
        }
    };

    const handleRegister = async () => {
        try {
            log('Registering...');
            await registerUser(form.username, form.password, form.phoneNumber);
            log('Registration successful! Redirecting to login...', 'success');
            
            setTimeout(() => {
                const targetPath = returnTo 
                    ? `/login?username=${encodeURIComponent(form.username)}&return_to=${encodeURIComponent(returnTo)}` // Pass return_to if present
                    : `/login?username=${encodeURIComponent(form.username)}`;
                window.location.href = targetPath;
            }, 1000);

        } catch (e) {
            log(e.message || 'Registration failed', 'error');
        }
    };

    return (
        <div className="auth-container">
            <div className="auth-header">
                <h2>Create Account</h2>
                <p className="text-sm">Join us today</p>
            </div>
            
            <div className="animate-fade-in">
                <div className="form-group">
                    <input className="form-control" name="username" placeholder="Username" onChange={handleChange} />
                </div>
                <div className="form-group">
                    <input className="form-control" name="password" type="password" placeholder="Password" onChange={handleChange} />
                </div>
                <div className="form-group">
                    <input className="form-control" name="phoneNumber" placeholder="Phone Number" onChange={handleChange} />
                </div>
                <button className="btn" onClick={handleRegister}>Register</button>
                <div className="text-center" style={{ marginTop: '1rem' }}>
                    <span className="text-sm">Already have an account? </span>
                    <a href={returnTo ? `/login?return_to=${encodeURIComponent(returnTo)}` : "/login"}>Login here</a>
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

export default Register;
