
# Readraa - Full Website (Frontend + Backend)

This package contains a complete, working version of your Readraa website with a Node.js + Express backend using JSON file storage.

## How to run locally

1. Install Node.js (v14+ recommended).
2. In the project folder run:
   ```
   npm install
   npm start
   ```
3. Open `http://localhost:5000` in your browser.

## What is included
- `server.js` - Express server with auth & API routes
- `data.json` - stores users and sample PDF list
- `public/index.html` - your frontend (with JS wired to backend)
- `package.json` - dependencies & start script

## Notes
- JWT secret and PORT can be configured with environment variables `JWT_SECRET` and `PORT`.
- Passwords are hashed with bcryptjs.
- Data persists in `data.json`.

