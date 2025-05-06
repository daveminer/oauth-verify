import { useState, useEffect } from "react";
import axios from "axios";
import "./App.css";

interface AuthResponse {
  token: string;
  publicKey: string;
}

function App() {
  const [authUrl, setAuthUrl] = useState<string>("");
  const [token, setToken] = useState<string>("");
  const [publicKey, setPublicKey] = useState<string>("");
  const [error, setError] = useState<string>("");

  useEffect(() => {
    // Check if we're returning from OAuth
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get("code");

    if (code) {
      // We have a code, exchange it for a token
      handleCallback(code);
    } else {
      // Get the auth URL
      fetchAuthUrl();
    }
  }, []);

  const fetchAuthUrl = async () => {
    try {
      const response = await axios.get("http://localhost:3000/auth/google");
      setAuthUrl(response.data.url);
    } catch (err) {
      setError("Failed to get auth URL");
      console.error(err);
    }
  };

  const handleCallback = async (code: string) => {
    try {
      const response = await axios.get<AuthResponse>(
        `http://localhost:3000/auth/google/callback?code=${code}`
      );
      setToken(response.data.token);
      setPublicKey(response.data.publicKey);
    } catch (err) {
      setError("Failed to exchange code for token");
      console.error(err);
    }
  };

  return (
    <div className="container">
      <h1>OAuth Demo</h1>

      {error && <div className="error">{error}</div>}

      {!token && authUrl && (
        <div className="auth-section">
          <h2>Authentication Required</h2>
          <a href={authUrl} className="auth-button">
            Sign in with Google
          </a>
        </div>
      )}

      {token && (
        <div className="token-section">
          <h2>Authentication Successful!</h2>

          <div className="token-display">
            <h3>JWT Token:</h3>
            <pre>{token}</pre>
          </div>

          <div className="public-key-display">
            <h3>Public Key:</h3>
            <pre>{publicKey}</pre>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
