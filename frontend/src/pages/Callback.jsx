import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

const Callback = () => {
    const [searchParams] = useSearchParams();
    const [code, setCode] = useState(null);

    useEffect(() => {
        const codeParam = searchParams.get('code');
        if (codeParam) {
            setCode(codeParam);
            // Here you would typically exchange the code for a token
            // using api.post('/oauth2/token', ...)
        }
    }, [searchParams]);

    return (
        <div style={{ padding: '20px', textAlign: 'center' }}>
            <h2>Login Successful</h2>
            {code ? (
                <div>
                    <p style={{ color: '#27ae60' }}>Authorization Code received!</p>
                    <code style={{ background: '#eee', padding: '5px' }}>{code}</code>
                </div>
            ) : (
                <p>Processing...</p>
            )}
        </div>
    );
};

export default Callback;
