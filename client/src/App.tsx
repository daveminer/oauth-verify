import { useState, useEffect } from "react";
import axios from "axios";
import "./App.css";
import { generateInputs } from "noir-jwt";
import {
  Contract,
  createPXEClient,
  loadContractArtifact,
} from "@aztec/aztec.js";
import { getInitialTestAccountsWallets } from "@aztec/accounts/testing";
import EasyPrivateVotingJson from "../../contracts/oauth_verify/target/easy_private_voting_contract-EasyPrivateVoting.json";
//import { CounterContractArtifact } from "@aztec/noir-contracts.js/Counter";

const DEPLOY_CONTRACT = true;

const EasyPrivateVotingContract = loadContractArtifact(
  EasyPrivateVotingJson as any
);

async function pemToJsonWebKey(pem: string): Promise<JsonWebKey> {
  // URL decode the PEM string first
  const decodedPem = decodeURIComponent(pem);

  // Remove PEM header, footer, and newlines
  const base64 = decodedPem
    .replace("-----BEGIN PUBLIC KEY-----", "")
    .replace("-----END PUBLIC KEY-----", "")
    .replace(/\n/g, "");

  // Convert base64 to binary
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  // Import the key
  const key = await window.crypto.subtle.importKey(
    "spki",
    bytes,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    true,
    ["verify"]
  );

  // Export as JsonWebKey
  return window.crypto.subtle.exportKey("jwk", key);
}

function App() {
  const [authUrl, setAuthUrl] = useState<string>("");
  const [token, setToken] = useState<string>("");
  const [publicKey, setPublicKey] = useState<string>("");
  const [error, setError] = useState<string>("");

  const PXE_URL = "http://localhost:8080";

  useEffect(() => {
    const processFn = async () => {
      // Check if we're returning from OAuth
      const urlParams = new URLSearchParams(window.location.search);
      const error = urlParams.get("error");

      if (error) {
        setError(error);
        return;
      }

      // Get the public key from cookie
      const publicKey = getCookie("public_key");
      console.log("PUBLIC KEY");
      console.log(publicKey);
      if (!publicKey) {
        // If no public key cookie, get the auth URL
        fetchAuthUrl();
        return;
      }

      setPublicKey(publicKey);

      let jwk: JsonWebKey;
      try {
        jwk = await pemToJsonWebKey(publicKey);
      } catch (err) {
        console.error("Error processing public key:", err);
        setError("Failed to process public key");
        return;
      }

      console.log("JWK");
      console.log(jwk);
      // Get the token from cookie
      const token = getCookie("auth_token");
      if (!token) {
        setError("No auth_token found");
        return;
      }

      setToken(token);

      const inputs = generateInputs({
        jwt: token,
        pubkey: jwk,
        maxSignedDataLength: 1024,
      });
      console.log(await inputs);

      // Call contract

      const pxe = await createPXEClient(PXE_URL);
      const { l1ChainId } = await pxe.getNodeInfo();
      console.log(`Connected to chain ${l1ChainId}`);

      const [ownerWallet] = await getInitialTestAccountsWallets(pxe);
      const ownerAddress = ownerWallet.getAddress();

      if (DEPLOY_CONTRACT) {
        const token = await Contract.deploy(
          ownerWallet,
          EasyPrivateVotingContract,
          [ownerAddress]
        )
          .send()
          .deployed();

        console.log(`Token deployed at ${token.address.toString()}`);

        //const addresses = { token: token.address.toString() };
        //writeFileSync("addresses.json", JSON.stringify(addresses, null, 2));
      }
    };

    processFn();
  }, []);

  // Helper function to get cookie value
  const getCookie = (name: string): string | null => {
    console.log("GET COOKIE");
    console.log(document.cookie);
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) {
      return parts.pop()?.split(";").shift() || null;
    }
    return null;
  };

  const fetchAuthUrl = async () => {
    try {
      const response = await axios.get("http://localhost:3000/auth/google", {
        withCredentials: true,
      });
      setAuthUrl(response.data.url);
    } catch (err) {
      setError("Failed to get auth URL");
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
