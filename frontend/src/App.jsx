import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import Login from './pages/Login';
import Register from './pages/Register';
import Consent from './pages/Consent';
import Callback from './pages/Callback';
import Error from './pages/Error';
import Home from './pages/Home';
import OAuth2Authorize from './pages/OAuth2Authorize';

function App() {
  return (
    <Router>
      <div style={{ fontFamily: 'sans-serif' }}>
        <nav style={{ padding: '10px', background: '#f8f9fa', borderBottom: '1px solid #ddd' }}>
          <Link to="/login" style={{ marginRight: '15px' }}>Login</Link>
          <Link to="/register" style={{ marginRight: '15px' }}>Register</Link>
          <Link to="/error">Error Test</Link>
        </nav>
        <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route path="/oauth2/consent" element={<Consent />} />
            <Route path="/callback" element={<Callback />} />
            <Route path="/error" element={<Error />} />
            <Route path="/oauth2/authorize" element={<OAuth2Authorize />} />
            <Route path="/" element={<Home />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
