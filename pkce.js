// Standalone Node.js script to generate PKCE parameters for OAuth2 testing
const crypto = require("crypto");

// Generate code_verifier (43-128 characters, base64url encoded random string)
function generateCodeVerifier() {
  const randomBytes = crypto.randomBytes(32);
  return base64URLEncode(randomBytes);
}

// Base64URL encode (without padding)
function base64URLEncode(buffer) {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

// Generate code_challenge (SHA256 hash of code_verifier, base64url encoded)
function generateCodeChallenge(verifier) {
  const hash = crypto.createHash("sha256").update(verifier).digest();
  return base64URLEncode(hash);
}

// Generate PKCE parameters
const codeVerifier = generateCodeVerifier();
const codeChallenge = generateCodeChallenge(codeVerifier);

console.log("\n=== PKCE Parameters Generated ===\n");
console.log("Code Verifier:", codeVerifier);
console.log("Code Challenge:", codeChallenge);
console.log("Code Challenge Method: S256");
console.log("\n=== Usage ===\n");
console.log("1. Use the Code Challenge in your authorization URL:");
console.log(`   code_challenge=${codeChallenge}&code_challenge_method=S256`);
console.log(
  "\n2. Use the Code Verifier when exchanging the authorization code for tokens:",
);
console.log(`   code_verifier=${codeVerifier}`);
console.log("\n=== Save these values! ===\n");
