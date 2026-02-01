import axios from "axios";

const API_BASE = "http://localhost:10000";

const api = axios.create({
  baseURL: API_BASE,
  withCredentials: true, // Important for cookies (SESSION, INIT-SESSION)
  headers: {
    "Content-Type": "application/json",
  },
});

// Helper: Base64URL to ArrayBuffer
const b64ToBuf = (b) => {
  return Uint8Array.from(atob(b.replace(/-/g, "+").replace(/_/g, "/")), (c) =>
    c.charCodeAt(0),
  );
};

// Helper: ArrayBuffer to Base64URL
const bufToBase64url = (buf) => {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
};

// --- Authentication Service Methods ---

export const checkUser = async (username) => {
  const response = await api.post("/auth/check-user-exist", {
    username,
    reason: "LOGIN",
  });
  return response.data;
};

export const registerUser = async (
  username,
  password,
  phoneNumber = "1234567890",
) => {
  const response = await api.post("/auth/register", {
    username,
    password,
    phoneNumber,
  });
  return response.data;
};

// --- Password Login ---

export const initPasswordLogin = async () => {
  const response = await api.post("/init/login/password");
  return response.data;
};

export const completePasswordLogin = async (credential) => {
  const response = await api.post("/init/login/password/complete", {
    credential,
  });
  return response.data;
};

// --- FIDO Registration ---

export const startFidoRegistration = async () => {
  try {
    console.log("Starting FIDO Registration Flow...");
    // 1. Init
    const initRes = await api.patch("/account/fido/register/init");
    const initData = initRes.data;
    console.log("FIDO Init Data:", initData);

    const options = JSON.parse(initData.options);
    console.log("Parsed Options:", options);

    // 2. Hardware Interaction
    if (options.publicKey) {
      options.publicKey.challenge = b64ToBuf(options.publicKey.challenge);
      options.publicKey.user.id = b64ToBuf(options.publicKey.user.id);

      // Force Platform Authenticator (TouchID/FaceID)
      if (!options.publicKey.authenticatorSelection) {
        options.publicKey.authenticatorSelection = {};
      }
      options.publicKey.authenticatorSelection.authenticatorAttachment =
        "platform";
    } else {
      // Fallback if options is the key itself (unlikely based on fido-test.html but possible)
      options.challenge = b64ToBuf(options.challenge);
      options.user.id = b64ToBuf(options.user.id);

      if (!options.authenticatorSelection) {
        options.authenticatorSelection = {};
      }
      options.authenticatorSelection.authenticatorAttachment = "platform";
    }

    console.log("Options with Buffers (Ready for navigator):", options);

    // Explicitly use publicKey property if it exists, otherwise use options itself (common confusion)
    const credentialOpts = options.publicKey
      ? { publicKey: options.publicKey }
      : { publicKey: options };

    console.log("Calling navigator.credentials.create with:", credentialOpts);

    const credential = await navigator.credentials.create(credentialOpts);

    console.log("Credential Created:", credential);

    // 3. Complete
    const payload = {
      response: JSON.stringify({
        id: credential.id,
        rawId: bufToBase64url(credential.rawId),
        type: credential.type,
        response: {
          attestationObject: bufToBase64url(
            credential.response.attestationObject,
          ),
          clientDataJSON: bufToBase64url(credential.response.clientDataJSON),
        },
        clientExtensionResults: credential.getClientExtensionResults(),
      }),
    };

    console.log("Sending Completion Payload:", payload);

    const completeRes = await api.post(
      "/account/fido/register/complete",
      payload,
    );
    return completeRes.data;
  } catch (err) {
    console.error("FIDO Registration Error:", err);
    throw err;
  }
};

// --- FIDO Login ---

export const initFidoLogin = async () => {
  const response = await api.post("/init/login/fido");
  console.log("FIDO Init Login Response:", response.data);
  // Store options for the next step, or return them
  return response.data;
};

export const completeFidoLogin = async (fidoOptions) => {
  try {
    console.log("Completing FIDO Login with options string:", fidoOptions);
    const options = JSON.parse(fidoOptions);
    console.log("Parsed FIDO Login Options:", options);

    if (options.publicKey) {
      options.publicKey.challenge = b64ToBuf(options.publicKey.challenge);
      options.publicKey.allowCredentials.forEach(
        (c) => (c.id = b64ToBuf(c.id)),
      );
    } else {
      options.challenge = b64ToBuf(options.challenge);
      options.allowCredentials.forEach((c) => (c.id = b64ToBuf(c.id)));
    }

    console.log("FIDO Login Options with Buffers:", options);

    const credentialOpts = options.publicKey
      ? { publicKey: options.publicKey }
      : { publicKey: options };
    console.log("Calling navigator.credentials.get with:", credentialOpts);

    const assertion = await navigator.credentials.get(credentialOpts);

    console.log("FIDO Assertion Received:", assertion);

    const payload = {
      response: JSON.stringify({
        id: assertion.id,
        rawId: bufToBase64url(assertion.rawId),
        type: assertion.type,
        response: {
          authenticatorData: bufToBase64url(
            assertion.response.authenticatorData,
          ),
          clientDataJSON: bufToBase64url(assertion.response.clientDataJSON),
          signature: bufToBase64url(assertion.response.signature),
          userHandle: assertion.response.userHandle
            ? bufToBase64url(assertion.response.userHandle)
            : null,
        },
        clientExtensionResults: assertion.getClientExtensionResults(),
      }),
    };

    console.log("Sending FIDO Login Completion Payload:", payload);

    const response = await api.post("/init/login/fido/complete", payload);
    return response.data;
  } catch (err) {
    console.error("FIDO Login Error:", err);
    throw err;
  }
};

// --- OAuth / Consent ---

export const approveConsent = async (clientId, scopes) => {
  // This typically isn't an API call to localhost:10000 but to the Authorization Server
  // However, if the frontend is the Authorization Server's UI, it might submit to it.
  // Based on standard flows, the frontend submits the form to the Authorization Endpoint
  // which then redirects back to the client.
  // Given the architecture, let's assume standard POST to /oauth2/authorize is manual details
  // But usually Consent is a POST to the authorization server to accept the consent.
  // Let's stub this for now or check how Spring Security expects consent.
  // Spring Security default consent page POSTs to /oauth2/authorize with 'consent_action=approve' usually?
  // Actually, strictly speaking, Spring Security Authorization Server expects a POST to /oauth2/authorize
  // with the same parameters + local authentication session.
  // We will revisit this when building the Consent page.
};

export default api;
