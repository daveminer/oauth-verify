import express, { Request, Response } from "express";
import cors from "cors";
import { OAuth2Client } from "google-auth-library";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import crypto from "crypto";
import cookieParser from "cookie-parser";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

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

    console.log("USER INFO");
    console.log(userInfo);

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

    console.log("TOKEN");
    console.log(token);

    // Set secure HTTP-only cookie with the token
    res.cookie("auth_token", token, {
      secure: true,
      sameSite: "lax",
      maxAge: 3600000, // 1 hour in milliseconds
      path: "/",
    });

    // Set public key in a separate cookie (since it's public anyway)
    res.cookie("public_key", publicKey, {
      secure: true,
      sameSite: "lax",
      maxAge: 3600000,
      path: "/",
    });

    // Redirect back to the Vite app
    res.redirect("http://localhost:5173");
  } catch (error) {
    console.error("Error during authentication:", error);
    res.redirect("http://localhost:5173?error=Authentication failed");
  }
});

// Get public key endpoint
app.get("/auth/public-key", (_req: Request, res: Response) => {
  res.json({ publicKey });
});

// Add a new endpoint to verify the token
app.get("/auth/verify", (req: Request, res: Response) => {
  const token = req.cookies.auth_token;
  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  try {
    const decoded = jwt.verify(token, publicKey);
    res.json({ user: decoded });
  } catch (error) {
    res.status(401).json({ error: "Invalid token" });
  }
});

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
