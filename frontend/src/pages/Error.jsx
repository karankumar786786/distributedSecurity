import React from 'react';
import { useSearchParams } from 'react-router-dom';

const Error = () => {
    const [searchParams] = useSearchParams();
    const message = searchParams.get('message') || 'An unknown error occurred.';

    return (
        <div style={{ padding: '20px', textAlign: 'center', color: '#c0392b' }}>
            <h2>Error</h2>
            <p>{message}</p>
            <a href="/login">Back to Login</a>
        </div>
    );
};

export default Error;
