const express = require("express");
const session = require("express-session");
const { Issuer, generators } = require("openid-client");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 6000;

app.use(
  session({
    name: "js_session",
    resave: false,
    saveUninitialized: true,
    secret: process.env.SESSION_SECRET,
  }),
);

let client;

// Initialize the OpenID Client
async function initClient() {
  const issuer = await Issuer.discover(process.env.ISSUER_URL);
  client = new issuer.Client({
    client_id: process.env.CLIENT_ID,
    client_secret: process.env.CLIENT_SECRET,
    redirect_uris: [process.env.REDIRECT_URI],
    response_types: ["code"],
  });
}

initClient().catch((err) => {
  console.error("Failed to initialize OpenID Client:", err);
  process.exit(1);
});

app.get("/", (req, res) => {
  if (req.session.user) {
    res.send(`
      <h1>Welcome ${req.session.user.sub}</h1>
      <pre>${JSON.stringify(req.session.user, null, 2)}</pre>
      <a href="/logout">Logout</a>
    `);
  } else {
    res.send('<h1>Home</h1><a href="/login">Login with OAuth2</a>');
  }
});

app.get("/login", (req, res) => {
  const nonce = generators.nonce();
  const state = generators.state();
  const code_verifier = generators.codeVerifier();
  const code_challenge = generators.codeChallenge(code_verifier);

  req.session.nonce = nonce;
  req.session.state = state;
  req.session.code_verifier = code_verifier;

  const authUrl = client.authorizationUrl({
    scope: "openid profile read",
    state,
    nonce,
    code_challenge,
    code_challenge_method: "S256",
  });

  res.redirect(authUrl);
});

app.get("/code/callback", async (req, res) => {
  const params = client.callbackParams(req);
  const tokenSet = await client.callback(process.env.REDIRECT_URI, params, {
    nonce: req.session.nonce,
    state: req.session.state,
    code_verifier: req.session.code_verifier,
  });

  console.log("received and validated tokens %j", tokenSet);
  console.log("validated ID Token claims %j", tokenSet.claims());

  req.session.user = tokenSet.claims();
  req.session.tokenSet = tokenSet;

  res.redirect("/");
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  res.redirect("/");
});

app.listen(port, () => {
  console.log(`JS Client listening at http://localhost:${port}`);
});
