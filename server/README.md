# OAuth Server

This is a simple Express server that implements Google OAuth2 authentication and generates JWTs.

## Setup

1. Install dependencies:
```bash
yarn install
```

2. Create a `.env` file in the server directory with the following variables:
```
PORT=3000
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URI=http://localhost:3000/auth/google/callback
```

3. Get Google OAuth credentials:
   - Go to the [Google Cloud Console](https://console.cloud.google.com)
   - Create a new project or select an existing one
   - Enable the Google+ API
   - Go to Credentials
   - Create an OAuth 2.0 Client ID
   - Add `http://localhost:3000/auth/google/callback` as an authorized redirect URI
   - Copy the client ID and client secret to your `.env` file

## Running the Server

Development mode:
```bash
yarn dev
```

Production mode:
```bash
yarn build
yarn start
```

## API Endpoints

1. `/auth/google`
   - GET request
   - Returns the Google OAuth URL to redirect the user to

2. `/auth/google/callback`
   - GET request
   - Callback URL for Google OAuth
   - Returns a JWT token and the public key used to sign it

3. `/auth/public-key`
   - GET request
   - Returns the public key used to verify JWTs

## JWT Format

The JWT contains the following claims:
- `sub`: Google user ID
- `email`: User's email address
- `name`: User's full name
- `picture`: URL to user's profile picture

The token is signed using RS256 (RSA Signature with SHA-256) and expires in 1 hour. 