import React, { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { getAuthToken } from '../services/api';

const OAuth2Authorize = () => {
    const location = useLocation();
    const navigate = useNavigate();
    const [error, setError] = useState(null);
    
    useEffect(() => {
        try {
            const token = getAuthToken();
            if (token) {
                // User is logged in, redirect to Authorization Server with token
                // We use standard query param "token" which we just enabled in SessionFilter
                const authServerUrl = new URL("http://localhost:12000/oauth2/authorize");
                
                // Use location.search directly to create params inside effect
                const query = new URLSearchParams(location.search);
                query.forEach((value, key) => authServerUrl.searchParams.set(key, value));
                
                authServerUrl.searchParams.set("token", token);
                
                console.log("Redirecting to Authorization Server with token...");
                window.location.href = authServerUrl.toString();
            } else {
                // User not logged in, redirect to login
                // Store the current full path and query in returnTo
                console.log("User not logged in, redirecting to login...");
                const currentPath = location.pathname + location.search;
                navigate(`/login?return_to=${encodeURIComponent(currentPath)}`);
            }
        } catch (err) {
            console.error("OAuth2 redirect error:", err);
            setError("Failed to construct authorization redirect. Please verify parameters.");
        }
    }, [location.pathname, location.search, navigate]); // Use specific properties to avoid loops

    if (error) {
        return (
            <div className="auth-container" style={{ textAlign: 'center', padding: '3rem' }}>
                <div className="auth-header">
                    <h2 style={{ color: '#ef4444' }}>⚠️ Authorization Error</h2>
                    <p>{error}</p>
                </div>
                <button className="btn" onClick={() => navigate('/')} style={{ marginTop: '1.5rem' }}>
                    Return Home
                </button>
            </div>
        );
    }

    return (
        <div className="auth-container" style={{ textAlign: 'center', padding: '3rem' }}>
            <div className="auth-header">
                <h2>🔐 OAuth2 Secure Gateway</h2>
                <p>Verifying your session...</p>
            </div>
            <div className="animate-pulse" style={{ marginTop: '2rem' }}>
                <div style={{ fontSize: '4rem' }}>🛡️</div>
            </div>
            <p className="text-sm" style={{ marginTop: '2rem', color: '#94a3b8' }}>
                Redirecting you to the authorization page.
            </p>
        </div>
    );
};

export default OAuth2Authorize;
