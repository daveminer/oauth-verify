import express, { Request, Response } from "express";
import cors from "cors";
import { OAuth2Client } from "google-auth-library";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import crypto from "crypto";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Generate RSA key pair
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: "spki",
    format: "pem",
  },
  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem",
  },
});

// Store the key pair
const keys = {
  publicKey,
  privateKey,
};

// Google OAuth2 client
const oauth2Client = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

interface GoogleUserInfo {
  sub: string;
  email: string;
  name: string;
  picture: string;
}

// Routes
app.get("/auth/google", (_req: Request, res: Response) => {
  const authUrl = oauth2Client.generateAuthUrl({
    access_type: "offline",
    scope: [
      "https://www.googleapis.com/auth/userinfo.profile",
      "https://www.googleapis.com/auth/userinfo.email",
    ],
  });
  res.json({ url: authUrl });
});

app.get("/auth/google/callback", async (req: Request, res: Response) => {
  const { code } = req.query;

  try {
    const { tokens } = await oauth2Client.getToken(code as string);
    oauth2Client.setCredentials(tokens);

    // Get user info
    const userInfo = await oauth2Client.request<GoogleUserInfo>({
      url: "https://www.googleapis.com/oauth2/v3/userinfo",
    });

    // Generate JWT
    const token = jwt.sign(
      {
        sub: userInfo.data.sub,
        email: userInfo.data.email,
        name: userInfo.data.name,
        picture: userInfo.data.picture,
      },
      privateKey,
      {
        algorithm: "RS256",
        expiresIn: "1h",
      }
    );

    // Return both the JWT and the public key
    res.json({
      token,
      publicKey: publicKey,
    });
  } catch (error) {
    console.error("Error during authentication:", error);
    res.status(500).json({ error: "Authentication failed" });
  }
});

// Get public key endpoint
app.get("/auth/public-key", (_req: Request, res: Response) => {
  res.json({ publicKey });
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
