import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { getAuthToken } from '../services/api';

const Consent = () => {
    const [searchParams] = useSearchParams();
    const [scopes, setScopes] = useState([]);
    const [clientId, setClientId] = useState('');
    
    // Store all params to relay back
    const [allParams, setAllParams] = useState({});

    useEffect(() => {
        const params = {};
        searchParams.forEach((value, key) => {
            params[key] = value;
        });
        console.log("DEBUG: Consent Page Received Params:", params);
        setAllParams(params);

        if (params.scope) {
             setScopes(params.scope.split(' '));
        }
        if (params.client_id) {
            setClientId(params.client_id);
        }
    }, [searchParams]);

    const handleConsent = (decision) => {
        if (!allParams.state) {
            alert("ERROR: Missing 'state' parameter! Cannot submit consent.");
            console.error("Missing 'state' in allParams:", allParams);
            return;
        }
        if (!allParams.client_id) {
            alert("ERROR: Missing 'client_id' parameter! Cannot submit consent.");
            console.error("Missing 'client_id' in allParams:", allParams);
            return;
        }

        const form = document.createElement('form');
        form.method = 'POST';
        form.action = 'http://localhost:12000/oauth2/authorize/process';

        const appendInput = (name, value) => {
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = name;
            input.value = value;
            form.appendChild(input);
        };

        // Add JWT token for stateless authentication
        const token = getAuthToken();
        if (token) {
            appendInput('token', token);
        } else {
            console.warn("DEBUG: No auth token found! Consent submission may fail.");
        }

        // Always include these core parameters
        appendInput('client_id', allParams.client_id);
        appendInput('state', allParams.state);
        
        if (allParams.redirect_uri) appendInput('redirect_uri', allParams.redirect_uri);
        if (allParams.response_type) appendInput('response_type', allParams.response_type);
        if (allParams.code_challenge) appendInput('code_challenge', allParams.code_challenge);
        if (allParams.code_challenge_method) appendInput('code_challenge_method', allParams.code_challenge_method);

        if (decision === 'approve') {
            // Signal approval to Spring Security
            appendInput('user_oauth_approval', 'true');
            
            console.log("DEBUG: Scopes array:", scopes);
            console.log("DEBUG: Scopes length:", scopes.length);
            
            // When approving, send each scope as a separate parameter
            scopes.forEach((scope, index) => {
                console.log(`DEBUG: Adding scope[${index}]:`, scope);
                appendInput('scope', scope);
            });
        } else {
            // Signal denial
            appendInput('user_oauth_approval', 'false');
        }
        
        console.log("DEBUG: Submitting Consent Form to:", form.action);
        console.log("DEBUG: Decision:", decision);
        console.log("DEBUG: Form inputs:", Array.from(form.elements).map(e => `${e.name}=${e.value}`));
        
        document.body.appendChild(form);
        form.submit();
    };

    return (
        <div className="auth-container">
            <div className="auth-header">
                <h2>Consent Required</h2>
                <p className="text-sm">Authorize request from <strong>{clientId}</strong></p>
            </div>
            
            <div className="animate-fade-in">
                <p style={{ marginBottom: '1rem', fontStyle: 'italic' }}>The application is requesting access to:</p>
                <div style={{ background: 'rgba(255,255,255,0.05)', borderRadius: '0.5rem', padding: '1rem', marginBottom: '1.5rem' }}>
                    <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
                        {scopes.map(s => (
                            <li key={s} style={{ display: 'flex', alignItems: 'center', marginBottom: '0.5rem' }}>
                                <span style={{ color: '#3b82f6', marginRight: '0.5rem' }}>✓</span>
                                {s}
                            </li>
                        ))}
                    </ul>
                </div>
                
                <div style={{ display: 'flex', gap: '1rem' }}>
                    <button 
                        className="btn"
                        onClick={() => handleConsent('approve')}
                        style={{ background: '#059669' }} 
                    >
                        Approve
                    </button>
                    <button 
                        className="btn btn-secondary"
                        onClick={() => handleConsent('deny')}
                        style={{ background: '#dc2626' }}
                    >
                        Deny
                    </button>
                </div>
            </div>
        </div>
    );
};

export default Consent;