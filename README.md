# Distributed OAuth2 Authorization Server 🔐

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.28+-326CE5?logo=kubernetes)](https://kubernetes.io/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2+-6DB33F?logo=spring)](https://spring.io/projects/spring-boot)
[![MongoDB](https://img.shields.io/badge/MongoDB-7.0+-47A248?logo=mongodb)](https://www.mongodb.com/)
[![ScyllaDB](https://img.shields.io/badge/ScyllaDB-5.4+-53CADD)](https://www.scylladb.com/)

> **A production-grade, multi-region OAuth2 authorization server** with hardware security key support, cryptographic password integrity verification, and zero-trust architecture.

---

## 🎯 Project Overview

This project implements a **distributed OAuth2/OIDC authorization server** designed for high-availability, security, and scalability. Built as a college project to demonstrate enterprise-grade architecture patterns, it incorporates cutting-edge security practices rarely seen in traditional OAuth2 implementations.

### Key Highlights

- 🔒 **Hardware Security Keys**: FIDO2/WebAuthn (YubiKey) integration for passwordless authentication
- 🛡️ **Cryptographic Integrity**: HMAC-based password integrity verification preventing database tampering
- 🌍 **Multi-Region**: Active-passive deployment with automatic failover
- 🔑 **Dynamic Key Management**: HashiCorp Vault integration with on-the-fly RSA key rotation
- 📊 **Full Observability**: Prometheus metrics, Loki logs, Tempo distributed tracing
- 🚀 **Cloud-Native**: Kubernetes with Istio service mesh, GitOps via ArgoCD
- ⚡ **High Performance**: Dragonfly (Redis-compatible) cache + ScyllaDB for token storage

---

## 📋 Table of Contents

- [Architecture](#-architecture)
- [Security Features](#-security-features)
- [Technology Stack](#-technology-stack)
- [Key Components](#-key-components)
- [Getting Started](#-getting-started)
- [Configuration](#-configuration)
- [API Documentation](#-api-documentation)
- [Multi-Region Setup](#-multi-region-setup)
- [Monitoring & Observability](#-monitoring--observability)
- [Security Best Practices](#-security-best-practices)
- [Performance Tuning](#-performance-tuning)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🏗️ Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Istio Service Mesh                        │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  mTLS • Circuit Breakers • Request Timeouts • Rate Limiting│ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                 │
                    ┌────────────┴────────────┐
                    │   Ingress Gateway       │
                    │   (TLS Termination)     │
                    └────────────┬────────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                        │                        │
┌───────▼───────┐       ┌───────▼───────┐       ┌───────▼───────┐
│ OAuth2 Service│       │ Passkey Service│       │  gRPC Service │
│  (Spring Boot)│       │  (WebAuthn)   │       │ (Argon2 Hash) │
└───────┬───────┘       └───────┬───────┘       └───────┬───────┘
        │                       │                        │
        └───────────┬───────────┴────────────────────────┘
                    │
        ┌───────────┼───────────────────────┐
        │           │                       │
┌───────▼─────┐ ┌──▼────────┐    ┌────────▼────────┐
│  MongoDB    │ │ ScyllaDB  │    │   Dragonfly     │
│ (User Data) │ │ (Tokens)  │    │ (Session Cache) │
└─────────────┘ └───────────┘    └─────────────────┘
                    │
        ┌───────────┼───────────────────────┐
        │           │                       │
┌───────▼─────┐ ┌──▼────────┐    ┌────────▼────────┐
│    Kafka    │ │   Vault   │    │  OpenTelemetry  │
│(Event Stream│ │ (Secrets) │    │   Collector     │
│   + Audit)  │ │           │    │                 │
└─────────────┘ └───────────┘    └─────────────────┘
```

### Multi-Region Deployment

```
┌─────────────────────────────────────────────────────────────────┐
│                     Region 1 (Primary - Active)                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ OAuth2 Pods  │  │  ScyllaDB    │  │    Kafka     │          │
│  │  (Serving)   │  │  (QUORUM)    │  │  (Producer)  │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                    ┌───────────▼────────────┐
                    │   Cross-Region Sync    │
                    │  • ScyllaDB Replication│
                    │  • Kafka Mirroring     │
                    │  • Vault DR Replication│
                    └───────────┬────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│                   Region 2 (Secondary - Passive)                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ OAuth2 Pods  │  │  ScyllaDB    │  │    Kafka     │          │
│  │ (Warm Standby│  │  (Replica)   │  │  (Consumer)  │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔒 Security Features

### 1. **Cryptographic Password Integrity** 🛡️

Traditional password storage uses bcrypt/Argon2, but **this implementation adds HMAC-based integrity verification** to detect database tampering.

#### How It Works

```java
// SecurityIntegrity.java - Password storage with HMAC
@Data
public class SecurityIntegrity {
    private String hashedPassword;        // Argon2 hash
    private String integrityHmacKeyId;    // Key rotation support
    private String integrityHmac;         // HMAC(key, hashedPassword)
}
```

**Architecture:**

```
┌──────────────────────────────────────────────────────────────┐
│  Step 1: Password Registration                               │
│                                                               │
│  User Password ─────► gRPC Service (Separate Platform)       │
│                         │                                     │
│                         ▼                                     │
│                    Argon2 Hashing                             │
│                    (Memory: 64MB, Iterations: 3)              │
│                         │                                     │
│                         ▼                                     │
│                  hashedPassword                               │
│                         │                                     │
│                         ▼                                     │
│  OAuth2 Service ◄───  Returns hash                            │
│       │                                                       │
│       ▼                                                       │
│  Fetch HMAC Key from Vault (rotates every 30 days)           │
│       │                                                       │
│       ▼                                                       │
│  HMAC-SHA256(key, hashedPassword) ──► Store in MongoDB       │
│                                                               │
│  MongoDB Document:                                            │
│  {                                                            │
│    "hashedPassword": "argon2$v=19$...",                       │
│    "integrityHmacKeyId": "key_version_42",                    │
│    "integrityHmac": "a3f8c9d2..."                             │
│  }                                                            │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│  Step 2: Password Verification (Login)                       │
│                                                               │
│  User Login ──► Fetch from MongoDB                            │
│                     │                                         │
│                     ▼                                         │
│  Verify Integrity:                                            │
│  1. Fetch HMAC key from Vault (using integrityHmacKeyId)      │
│  2. Recompute: HMAC-SHA256(key, hashedPassword)               │
│  3. Compare with stored integrityHmac                         │
│                     │                                         │
│                     ├──► If Match: ✅ Proceed to verify       │
│                     │                 password with gRPC      │
│                     │                                         │
│                     └──► If Mismatch: ❌ DATABASE TAMPERED    │
│                              │                                │
│                              ▼                                │
│                        Log security event                     │
│                        Lock account                           │
│                        Alert security team                    │
└──────────────────────────────────────────────────────────────┘
```

**Why This Matters:**
- ✅ Detects if an attacker modifies the database directly
- ✅ Prevents privilege escalation via database manipulation
- ✅ Keys rotate automatically via Vault (30-day cycle)
- ✅ Separate gRPC service ensures password hashing is isolated

---

### 2. **FIDO2/WebAuthn Hardware Security Keys** 🔑

Full support for passwordless authentication using YubiKey, Touch ID, Windows Hello, and other FIDO2 authenticators.

#### Implementation

```java
// FidoCredential.java - Stores public key and metadata
@Data
@Builder
public class FidoCredential {
    @Field("credential_id")
    private ByteArray credentialId;      // Unique credential identifier
    
    @Field("user_handle")
    private ByteArray userHandle;        // Links to user account
    
    @Field("public_key")
    private ByteArray publicKey;         // ECDSA P-256 public key
    
    @Field("signature_count")
    private long signatureCount;         // Prevents replay attacks
    
    @Field("name")
    private String name;                 // "My YubiKey 5C"
    
    @Field("integrity_hmac_key_id")
    private String integrityHmacKeyId;   // For key rotation
    
    @Field("integrity_hmac")
    private String integrityHmac;        // HMAC(key, publicKey)
}
```

**Registration Flow:**

```
┌────────────────────────────────────────────────────────────────┐
│  1. User Requests Passkey Registration                         │
│     POST /api/webauthn/register/start                          │
│                                                                 │
│  2. Server generates challenge                                 │
│     ┌─────────────────────────────────────┐                    │
│     │ Challenge: random 32-byte value     │                    │
│     │ User ID: user handle                │                    │
│     │ RP ID: oauth.example.com            │                    │
│     │ Algorithms: ES256, RS256            │                    │
│     └─────────────────────────────────────┘                    │
│                                                                 │
│  3. Browser/Client calls navigator.credentials.create()        │
│     User touches YubiKey                                        │
│                                                                 │
│  4. Client sends attestation                                   │
│     POST /api/webauthn/register/finish                         │
│     {                                                           │
│       "credentialId": "base64...",                              │
│       "publicKey": "base64...",                                 │
│       "attestation": {...}                                      │
│     }                                                           │
│                                                                 │
│  5. Server verifies and stores                                 │
│     • Validate attestation signature                           │
│     • Extract public key                                       │
│     • Generate HMAC for integrity                              │
│     • Store in MongoDB                                         │
└────────────────────────────────────────────────────────────────┘
```

**Authentication Flow:**

```
┌────────────────────────────────────────────────────────────────┐
│  1. User clicks "Sign in with Passkey"                         │
│     POST /api/webauthn/authenticate/start                      │
│                                                                 │
│  2. Server fetches stored credential                           │
│     • Verify HMAC integrity of stored public key               │
│     • Generate new challenge                                   │
│                                                                 │
│  3. Client calls navigator.credentials.get()                   │
│     User touches YubiKey                                        │
│                                                                 │
│  4. Client sends assertion                                     │
│     POST /api/webauthn/authenticate/finish                     │
│     {                                                           │
│       "credentialId": "base64...",                              │
│       "signature": "base64...",                                 │
│       "authenticatorData": "base64..."                          │
│     }                                                           │
│                                                                 │
│  5. Server verifies signature                                  │
│     • Increment signature counter (prevent replay)             │
│     • Verify signature using stored public key                 │
│     • Issue OAuth2 tokens                                      │
└────────────────────────────────────────────────────────────────┘
```

**Security Properties:**
- ✅ **Phishing-resistant**: Cryptographically bound to domain
- ✅ **Replay-protected**: Signature counter increments
- ✅ **Tamper-evident**: HMAC integrity on public keys
- ✅ **User presence**: Requires physical touch

---

### 3. **OAuth2 Security Enhancements** 🔐

#### PKCE (Proof Key for Code Exchange)

Prevents authorization code interception attacks in public clients.

```
Authorization Request:
  code_challenge = BASE64URL(SHA256(code_verifier))
  code_challenge_method = S256

Token Request:
  code_verifier = original_random_value
  
Server validates:
  SHA256(code_verifier) == code_challenge
```

#### Nonce (Prevents Replay Attacks)

```
Authorization Request:
  nonce = random_value_123
  
ID Token (JWT):
  {
    "nonce": "random_value_123",
    "iat": 1738789200
  }

Client validates nonce matches original request.
```

---

### 4. **Device Fingerprinting & Anomaly Detection** 🖥️

```java
// SecurityEvent.java - Audit trail for security events
@Data
@Builder
public class SecurityEvent {
    private ObjectId id;
    private ObjectId user;
    private String deviceHashKeyId;     // Key ID for HMAC rotation
    private String deviceHash;          // HMAC(key, deviceFingerprint)
    private String ipAddress;
    private Event event;                // LOGIN, FAILED_LOGIN, PASSKEY_ADDED
    private String message;
    private Instant createdAt;
}
```

**Device Fingerprinting:**

```
Device Fingerprint = SHA256(
    User-Agent +
    Accept-Language +
    Screen Resolution +
    Timezone +
    Canvas Hash +
    WebGL Hash
)

Stored as: HMAC(vault_key, fingerprint)
```

**Anomaly Detection:**

```java
// User.java - Track known devices and lock suspicious activity
private List<String> knownDeviceHashes;
private boolean isAccountLocked;
private int numberOfInitiatedOperations;
private LocalDateTime lockingTime;
```

**Flow:**

```
Login Attempt
    ↓
Generate Device Hash
    ↓
Check if hash in knownDeviceHashes
    ↓
    ├─► Known Device: Allow
    │
    └─► Unknown Device:
            ├─► Send email verification
            ├─► Log SecurityEvent to Kafka
            ├─► Require MFA (TOTP/Passkey)
            └─► Add to knownDeviceHashes if verified
```

---

### 5. **Key Management with HashiCorp Vault** 🗝️

#### RSA Key Rotation for JWT Signing

```
┌─────────────────────────────────────────────────────────────┐
│  Vault Secrets Engine: Transit                              │
│                                                              │
│  Key: oauth2-jwt-signing                                    │
│  Type: RSA-4096                                              │
│  Auto-Rotation: Every 30 days                                │
│                                                              │
│  Versions:                                                   │
│    • Version 1: 2024-12-01 (archived)                        │
│    • Version 2: 2025-01-01 (active signing)                  │
│    • Version 3: 2025-02-01 (active signing + verification)   │
│                                                              │
│  Old tokens signed with v2 still verify with v2 public key   │
└─────────────────────────────────────────────────────────────┘
```

**Implementation:**

```java
// Fetch current signing key
VaultResponse response = vaultTemplate.read("transit/keys/oauth2-jwt-signing");
String publicKeyPEM = response.getData().get("latest_version");

// Sign JWT
String jwt = Jwts.builder()
    .setSubject(username)
    .signWith(vaultPrivateKey)  // Vault signs internally
    .compact();

// Verification uses JWKS endpoint
GET /.well-known/jwks.json
{
  "keys": [
    {
      "kid": "vault-v3",
      "kty": "RSA",
      "use": "sig",
      "n": "base64...",
      "e": "AQAB"
    }
  ]
}
```

#### HMAC Keys for Integrity Verification

```
┌─────────────────────────────────────────────────────────────┐
│  Vault KV Secrets Engine v2                                 │
│                                                              │
│  Path: secret/data/hmac-keys                                 │
│                                                              │
│  Keys:                                                       │
│    password-integrity-key-42:  "base64_encoded_secret"       │
│    device-hash-key-42:         "base64_encoded_secret"       │
│    fido-pubkey-integrity-42:   "base64_encoded_secret"       │
│                                                              │
│  Rotation Policy: 30 days                                    │
│  Access: OAuth2 service role only                            │
└─────────────────────────────────────────────────────────────┘
```

**MongoDB Storage Pattern:**

```json
{
  "_id": ObjectId("..."),
  "username": "alice@example.com",
  "security": {
    "hashedPassword": "argon2$v=19$m=65536...",
    "integrityHmacKeyId": "password-integrity-key-42",
    "integrityHmac": "a3f8c9d2e1b4f5a6..."
  },
  "fidoCredential": {
    "publicKey": "base64_encoded_ecdsa_pubkey",
    "integrityHmacKeyId": "fido-pubkey-integrity-42",
    "integrityHmac": "f9e8d7c6b5a4..."
  }
}
```

**Benefits:**
- ✅ Centralized secret management
- ✅ Automated key rotation (zero-downtime)
- ✅ Audit trail of all key access
- ✅ Prevents hardcoded secrets in code

---

### 6. **Separate gRPC Service for Password Hashing** 🔧

To ensure **defense in depth**, password hashing is isolated in a dedicated microservice.

**Architecture:**

```
┌──────────────────────────────────────────────────────────────┐
│  OAuth2 Service (Spring Boot)                                │
│                                                               │
│  POST /api/auth/register                                      │
│  {                                                            │
│    "username": "alice@example.com",                           │
│    "password": "SecureP@ssw0rd!"                              │
│  }                                                            │
│                                                               │
│  ↓ Sends password to gRPC service                             │
│                                                               │
└────────────────────┬──────────────────────────────────────────┘
                     │
                     │ gRPC Call (mTLS encrypted)
                     │
                     ▼
┌──────────────────────────────────────────────────────────────┐
│  Password Hashing Service (Go/Java)                          │
│                                                               │
│  service PasswordHasher {                                     │
│    rpc HashPassword(PasswordRequest)                          │
│        returns (PasswordResponse);                            │
│                                                               │
│    rpc VerifyPassword(VerifyRequest)                          │
│        returns (VerifyResponse);                              │
│  }                                                            │
│                                                               │
│  Implementation:                                              │
│    • Argon2id (Memory: 64MB, Iterations: 3, Parallelism: 4)  │
│    • Salt: 16 bytes (random per password)                     │
│    • Output: 32 bytes                                         │
│                                                               │
│  Returns: "argon2$v=19$m=65536,t=3,p=4$base64salt$base64hash" │
└──────────────────────────────────────────────────────────────┘
```

**Why Separate Service?**

| Benefit | Explanation |
|---------|-------------|
| **Resource Isolation** | Password hashing is CPU-intensive (Argon2 uses 64MB RAM per hash). Separate service prevents it from starving OAuth2 API threads. |
| **Horizontal Scaling** | Can scale password hashing pods independently (e.g., 10 OAuth2 pods, 3 hashing pods). |
| **Security Boundary** | Plaintext passwords never touch OAuth2 service memory. gRPC service can run in a separate security zone with stricter network policies. |
| **Technology Choice** | Can use Go/Rust for faster Argon2 implementation while keeping OAuth2 in Java/Spring. |
| **Audit Trail** | All password operations logged separately for compliance. |

**gRPC Protocol Definition:**

```protobuf
syntax = "proto3";

package auth;

service PasswordHasher {
  // Hash a plaintext password
  rpc HashPassword(HashPasswordRequest) returns (HashPasswordResponse);
  
  // Verify password against hash
  rpc VerifyPassword(VerifyPasswordRequest) returns (VerifyPasswordResponse);
}

message HashPasswordRequest {
  string password = 1;
}

message HashPasswordResponse {
  string hashed_password = 1;
  string algorithm_info = 2;  // "argon2id(m=64MB,t=3,p=4)"
}

message VerifyPasswordRequest {
  string password = 1;
  string hashed_password = 2;
}

message VerifyPasswordResponse {
  bool is_valid = 1;
  bool needs_rehash = 2;  // If params changed (e.g., upgraded to 128MB)
}
```

---

## 💻 Technology Stack

### Core Services

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| **OAuth2 Server** | Spring Boot | 3.2+ | Authorization server (RFC 6749, OIDC) |
| **Password Hashing** | gRPC Service | - | Argon2id hashing (isolated microservice) |
| **Passkey Service** | Spring Boot + Yubico WebAuthn | 2.5+ | FIDO2/WebAuthn authentication |
| **User Database** | MongoDB | 7.0+ | User profiles, credentials, device hashes |
| **Token Store** | ScyllaDB | 5.4+ | OAuth tokens (high-write throughput) |
| **Session Cache** | Dragonfly | 1.14+ | Session data, rate limiting counters |
| **Secret Management** | HashiCorp Vault | 1.15+ | RSA keys, HMAC keys, encryption keys |
| **Event Streaming** | Apache Kafka | 3.6+ | Audit logs, cross-region replication |

### Infrastructure

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Orchestration** | Kubernetes | 1.28+ |
| **Service Mesh** | Istio | 1.20+ |
| **GitOps** | ArgoCD | 2.9+ |
| **Ingress** | Istio Gateway | TLS termination, routing |
| **Container Registry** | Harbor | Image scanning, signing |

### Observability

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Metrics** | Prometheus | Time-series metrics |
| **Logs** | Loki | Centralized logging |
| **Traces** | Tempo | Distributed tracing |
| **Visualization** | Grafana | Dashboards |
| **APM** | OpenTelemetry | Unified telemetry |

### CI/CD

| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Source Control** | Git | Version control |
| **CI Pipeline** | GitHub Actions / Jenkins | Build, test, scan |
| **Code Quality** | SonarQube | Static analysis |
| **Image Scanning** | Trivy / Grype | Vulnerability scanning |
| **Helm Charts** | Helm | Kubernetes packaging |

---

## 🧩 Key Components

### 1. User Entity

```java
@Document(collection = "security")
@Data
@Builder
public class User implements UserDetails {
    @Id
    private ObjectId id;
    
    @Indexed(unique = true)
    private String username;
    
    // Password integrity with HMAC
    private SecurityIntegrity security;
    
    // FIDO2/WebAuthn credential
    private FidoCredential fidoCredential;
    
    // Multi-factor recovery
    private String backupEmail;
    private String phoneNumber;
    private boolean backupEmailVerified;
    private boolean phoneNumberVerified;
    
    // Device tracking
    private List<String> knownDeviceHashes;
    
    // Account security
    private boolean isAccountLocked;
    private LocalDateTime lockingTime;
    private int numberOfInitiatedOperations;  // Rate limiting
    
    // Feature flags
    private boolean passkeyEnabled;
}
```

### 2. Security Integrity Keys

```java
// Stored in MongoDB (encrypted at rest)
@Document("security_keys")
@Data
@Builder
public class SecurityIntegrityKeyEntity {
    @Id
    private ObjectId id;
    private String encryptedKey;  // Encrypted with Vault's transit engine
}

// FIDO-specific keys
@Document("security_fido_keys")
@Data
@Builder
public class SecurityIntegrityFidoKeyEntity {
    @Id
    private ObjectId id;
    private String key;  // Used for HMAC(publicKey)
}
```

### 3. Security Event Audit

```java
@Data
@Builder
public class SecurityEvent {
    private ObjectId id;
    private ObjectId user;
    private String deviceHashKeyId;
    private String deviceHash;
    private String ipAddress;
    private Event event;  // Enum: LOGIN, FAILED_LOGIN, PASSKEY_ADDED, etc.
    private String message;
    private Instant createdAt;
}
```

**Event Types:**

```java
public enum Event {
    LOGIN,
    LOGOUT,
    FAILED_LOGIN,
    ACCOUNT_LOCKED,
    PASSWORD_CHANGED,
    PASSKEY_REGISTERED,
    PASSKEY_REMOVED,
    DEVICE_ADDED,
    SUSPICIOUS_LOGIN,
    MFA_ENABLED,
    MFA_DISABLED,
    TOKEN_ISSUED,
    TOKEN_REVOKED
}
```

**Kafka Topic Structure:**

```
Topic: security-events

Message:
{
  "eventId": "550e8400-e29b-41d4-a716-446655440000",
  "userId": "507f1f77bcf86cd799439011",
  "username": "alice@example.com",
  "event": "SUSPICIOUS_LOGIN",
  "deviceHash": "hmac_sha256_...",
  "ipAddress": "203.0.113.45",
  "location": "New York, US",
  "timestamp": "2025-02-08T14:30:00Z",
  "metadata": {
    "userAgent": "Mozilla/5.0...",
    "reason": "Unknown device from new country"
  }
}
```

---

## 🚀 Getting Started

### Prerequisites

- **Docker** 24.0+
- **Kubernetes** 1.28+ (Minikube, Kind, or cloud provider)
- **Helm** 3.13+
- **kubectl** 1.28+
- **Java** 21+ (for local development)
- **Maven** 3.9+

### Local Development Setup

#### 1. Clone Repository

```bash
git clone https://github.com/karankumar786786/distributedSecurity.git
cd distributedSecurity
```

#### 2. Start Infrastructure (Docker Compose)

```bash
docker-compose up -d

# Services started:
# - MongoDB (27017)
# - ScyllaDB (9042)
# - Dragonfly (6379)
# - Kafka (9092)
# - Vault (8200)
# - Prometheus (9090)
# - Grafana (3000)
```

#### 3. Initialize Vault

```bash
# Unseal Vault
export VAULT_ADDR='http://localhost:8200'
vault operator init
vault operator unseal <unseal_key_1>
vault operator unseal <unseal_key_2>
vault operator unseal <unseal_key_3>

# Enable secrets engines
vault login <root_token>
vault secrets enable -path=secret kv-v2
vault secrets enable transit

# Create RSA key for JWT signing
vault write transit/keys/oauth2-jwt-signing type=rsa-4096

# Create HMAC keys
vault kv put secret/hmac-keys \
  password-integrity-key-1="$(openssl rand -base64 32)" \
  device-hash-key-1="$(openssl rand -base64 32)" \
  fido-pubkey-integrity-1="$(openssl rand -base64 32)"
```

#### 4. Run gRPC Password Service

```bash
cd services/password-hasher
./gradlew bootRun

# Service runs on localhost:50051
```

#### 5. Run OAuth2 Service

```bash
cd services/oauth2-server
./mvnw spring-boot:run

# Service runs on localhost:8080
```

#### 6. Run Passkey Service

```bash
cd services/passkey-service
./mvnw spring-boot:run

# Service runs on localhost:8081
```

### Kubernetes Deployment

#### 1. Install Istio

```bash
istioctl install --set profile=demo -y
kubectl label namespace default istio-injection=enabled
```

#### 2. Deploy Infrastructure

```bash
# Add Helm repos
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo add scylladb https://scylla-operator-charts.storage.googleapis.com/stable
helm repo add hashicorp https://helm.releases.hashicorp.com
helm repo update

# Deploy MongoDB
helm install mongodb bitnami/mongodb \
  --set auth.enabled=true \
  --set auth.rootPassword=changeme \
  --set replicaCount=3

# Deploy ScyllaDB
kubectl apply -f k8s/scylladb/

# Deploy Dragonfly
helm install dragonfly bitnami/redis \
  --set image.repository=docker.dragonflydb.io/dragonflydb/dragonfly \
  --set image.tag=v1.14.0

# Deploy Kafka
helm install kafka bitnami/kafka \
  --set replicaCount=3 \
  --set zookeeper.enabled=true

# Deploy Vault
helm install vault hashicorp/vault \
  --set server.ha.enabled=true \
  --set server.ha.replicas=3
```

#### 3. Deploy Application

```bash
# Build and push images
docker build -t oauth2-server:latest services/oauth2-server/
docker build -t password-hasher:latest services/password-hasher/
docker build -t passkey-service:latest services/passkey-service/

# Push to registry
docker tag oauth2-server:latest registry.example.com/oauth2-server:latest
docker push registry.example.com/oauth2-server:latest

# Deploy with ArgoCD
kubectl apply -f argocd/applications/
```

---

## ⚙️ Configuration

### Environment Variables

```bash
# OAuth2 Server
SPRING_DATA_MONGODB_URI=mongodb://mongodb:27017/oauth2
SPRING_KAFKA_BOOTSTRAP_SERVERS=kafka:9092
VAULT_URI=http://vault:8200
VAULT_TOKEN=s.xxxxxxxxxxxxxxxx
GRPC_PASSWORD_SERVICE_HOST=password-hasher
GRPC_PASSWORD_SERVICE_PORT=50051
DRAGONFLY_HOST=dragonfly
DRAGONFLY_PORT=6379
SCYLLADB_CONTACT_POINTS=scylladb-0,scylladb-1,scylladb-2
SCYLLADB_KEYSPACE=oauth2_tokens

# Passkey Service
WEBAUTHN_RP_ID=oauth.example.com
WEBAUTHN_RP_NAME=Distributed OAuth2 Server
WEBAUTHN_ORIGIN=https://oauth.example.com
```

### Vault Configuration

```hcl
# vault-config.hcl
storage "raft" {
  path = "/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 0
  tls_cert_file = "/vault/tls/cert.pem"
  tls_key_file  = "/vault/tls/key.pem"
}

ui = true

api_addr = "https://vault.example.com:8200"
cluster_addr = "https://vault-0.vault:8201"
```

### Istio Configuration

```yaml
# Circuit Breaker
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: oauth2-circuit-breaker
spec:
  host: oauth2-service
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 100
      http:
        http1MaxPendingRequests: 50
        http2MaxRequests: 100
        maxRequestsPerConnection: 2
    outlierDetection:
      consecutiveErrors: 5
      interval: 30s
      baseEjectionTime: 30s
      maxEjectionPercent: 50
      minHealthPercent: 40
```

```yaml
# Rate Limiting
apiVersion: networking.istio.io/v1beta1
kind: EnvoyFilter
metadata:
  name: oauth2-rate-limit
spec:
  configPatches:
  - applyTo: HTTP_FILTER
    match:
      context: SIDECAR_INBOUND
    patch:
      operation: INSERT_BEFORE
      value:
        name: envoy.filters.http.local_ratelimit
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit
          stat_prefix: http_local_rate_limiter
          token_bucket:
            max_tokens: 100
            tokens_per_fill: 10
            fill_interval: 1s
```

---

## 📚 API Documentation

### OAuth2 Endpoints

#### 1. Authorization Endpoint

```http
GET /oauth2/authorize?
  response_type=code&
  client_id=client123&
  redirect_uri=https://app.example.com/callback&
  scope=openid profile email&
  state=abc123&
  nonce=xyz789&
  code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
  code_challenge_method=S256

Response:
302 Redirect to: https://app.example.com/callback?code=AUTH_CODE&state=abc123
```

#### 2. Token Endpoint

```http
POST /oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTH_CODE&
redirect_uri=https://app.example.com/callback&
client_id=client123&
client_secret=secret456&
code_verifier=ORIGINAL_RANDOM_VALUE

Response:
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_token_here",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "scope": "openid profile email"
}
```

#### 3. UserInfo Endpoint

```http
GET /oauth2/userinfo
Authorization: Bearer ACCESS_TOKEN

Response:
{
  "sub": "507f1f77bcf86cd799439011",
  "username": "alice@example.com",
  "email": "alice@example.com",
  "email_verified": true,
  "passkey_enabled": true,
  "mfa_enabled": true
}
```

### WebAuthn Endpoints

#### 1. Register Passkey (Start)

```http
POST /api/webauthn/register/start
Authorization: Bearer ACCESS_TOKEN

Response:
{
  "challenge": "base64_encoded_challenge",
  "rp": {
    "name": "Distributed OAuth2 Server",
    "id": "oauth.example.com"
  },
  "user": {
    "id": "base64_user_handle",
    "name": "alice@example.com",
    "displayName": "Alice"
  },
  "pubKeyCredParams": [
    {"type": "public-key", "alg": -7},  // ES256
    {"type": "public-key", "alg": -257} // RS256
  ],
  "timeout": 60000,
  "attestation": "none"
}
```

#### 2. Register Passkey (Finish)

```http
POST /api/webauthn/register/finish
Authorization: Bearer ACCESS_TOKEN
Content-Type: application/json

{
  "id": "credential_id_base64",
  "rawId": "credential_id_base64",
  "response": {
    "clientDataJSON": "base64...",
    "attestationObject": "base64..."
  },
  "type": "public-key",
  "name": "My YubiKey 5C"
}

Response:
{
  "success": true,
  "credentialId": "credential_id_base64",
  "message": "Passkey registered successfully"
}
```

#### 3. Authenticate with Passkey (Start)

```http
POST /api/webauthn/authenticate/start
Content-Type: application/json

{
  "username": "alice@example.com"
}

Response:
{
  "challenge": "base64_encoded_challenge",
  "timeout": 60000,
  "rpId": "oauth.example.com",
  "allowCredentials": [
    {
      "type": "public-key",
      "id": "credential_id_base64"
    }
  ],
  "userVerification": "required"
}
```

#### 4. Authenticate with Passkey (Finish)

```http
POST /api/webauthn/authenticate/finish
Content-Type: application/json

{
  "id": "credential_id_base64",
  "rawId": "credential_id_base64",
  "response": {
    "clientDataJSON": "base64...",
    "authenticatorData": "base64...",
    "signature": "base64...",
    "userHandle": "base64..."
  },
  "type": "public-key"
}

Response:
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_token_here",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

## 🌍 Multi-Region Setup

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                   Global Traffic Manager (Route53)              │
│                    Health Check: /health/ready                  │
└────────────────────────┬────────────────────────────────────────┘
                         │
         ┌───────────────┴────────────────┐
         │                                │
┌────────▼───────────┐          ┌────────▼───────────┐
│   Region: us-east  │          │   Region: eu-west  │
│   (Primary/Active) │          │  (Secondary/Passive)│
│                    │          │                    │
│  OAuth2 Pods: 10   │          │  OAuth2 Pods: 10   │
│  ScyllaDB: RF=3    │◄────────►│  ScyllaDB: RF=3    │
│  Kafka: Active     │  Sync    │  Kafka: Mirroring  │
│  Vault: Primary    │          │  Vault: DR Replica │
└────────────────────┘          └────────────────────┘
```

### ScyllaDB Multi-DC Replication

```cql
-- Create keyspace with multi-DC replication
CREATE KEYSPACE oauth2_tokens
WITH replication = {
  'class': 'NetworkTopologyStrategy',
  'us-east': 3,
  'eu-west': 3
}
AND durable_writes = true;

-- Token table
CREATE TABLE oauth2_tokens.access_tokens (
  token_id UUID PRIMARY KEY,
  user_id UUID,
  client_id TEXT,
  scopes SET<TEXT>,
  issued_at TIMESTAMP,
  expires_at TIMESTAMP,
  token_hash TEXT
) WITH default_time_to_live = 3600
  AND gc_grace_seconds = 86400;
```

**Consistency Levels:**

```java
// Write tokens with QUORUM (2 of 3 nodes in local DC)
SimpleStatement insertToken = SimpleStatement.builder(
    "INSERT INTO access_tokens (token_id, user_id, ...) VALUES (?, ?, ...)")
    .setConsistencyLevel(ConsistencyLevel.LOCAL_QUORUM)
    .build();

// Read tokens with LOCAL_ONE (fast reads from nearest node)
SimpleStatement selectToken = SimpleStatement.builder(
    "SELECT * FROM access_tokens WHERE token_id = ?")
    .setConsistencyLevel(ConsistencyLevel.LOCAL_ONE)
    .build();
```

### Kafka Cross-Region Mirroring

```yaml
# kafka-mirror-maker.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kafka-mirror-maker
data:
  consumer.properties: |
    bootstrap.servers=kafka-us-east:9092
    group.id=mirror-maker-group
    auto.offset.reset=earliest
  
  producer.properties: |
    bootstrap.servers=kafka-eu-west:9092
    acks=all
    retries=3
  
  whitelist: |
    security-events
    audit-logs
```

### Vault DR Replication

```bash
# On primary (us-east)
vault write -f sys/replication/dr/primary/enable
vault write sys/replication/dr/primary/secondary-token id=eu-west

# On secondary (eu-west)
vault write sys/replication/dr/secondary/enable token=<TOKEN>
```

### Failover Procedure

```bash
# 1. Detect primary failure (Prometheus alert)
alert: RegionDown
expr: up{job="oauth2-service",region="us-east"} == 0
for: 2m

# 2. Promote secondary Kafka to active
kafka-configs --bootstrap-server kafka-eu-west:9092 \
  --alter --entity-type brokers \
  --entity-name 0 \
  --add-config unclean.leader.election.enable=true

# 3. Update Route53 DNS (TTL: 60s)
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890ABC \
  --change-batch '{
    "Changes": [{
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "oauth.example.com",
        "Type": "A",
        "SetIdentifier": "Primary",
        "Failover": "PRIMARY",
        "TTL": 60,
        "ResourceRecords": [{"Value": "EU_WEST_IP"}]
      }
    }]
  }'

# 4. Promote Vault DR secondary (if needed)
vault write -f sys/replication/dr/secondary/promote

# 5. Verify token consistency
scylla-nodetool status
# Check replication lag < 100ms
```

**Recovery Time Objective (RTO):** < 5 minutes  
**Recovery Point Objective (RPO):** < 1 second (ScyllaDB async replication)

---

## 📊 Monitoring & Observability

### Prometheus Metrics

```yaml
# OAuth2 Service Metrics
# Token issuance rate
oauth2_tokens_issued_total{type="access_token"}
oauth2_tokens_issued_total{type="refresh_token"}

# Authentication metrics
oauth2_auth_attempts_total{method="password",result="success"}
oauth2_auth_attempts_total{method="passkey",result="success"}
oauth2_auth_attempts_total{result="failed"}

# Password integrity violations
security_integrity_violations_total{type="password"}
security_integrity_violations_total{type="fido_pubkey"}

# Device anomalies
security_unknown_device_detections_total
security_account_locks_total

# Vault operations
vault_key_rotation_total{key="oauth2-jwt-signing"}
vault_hmac_fetch_duration_seconds

# gRPC metrics
grpc_server_handled_total{method="HashPassword"}
grpc_server_handling_seconds{method="VerifyPassword"}

# Istio metrics
istio_requests_total{destination_service="oauth2-service"}
istio_request_duration_milliseconds{destination_service="oauth2-service"}
istio_tcp_connections_opened_total
```

### Grafana Dashboards

**Dashboard 1: OAuth2 Overview**

```
+─────────────────────────────────────────────────────────+
│  Token Issuance Rate (req/sec)                          │
│  ▂▃▅▇█▇▅▃▂ Access Tokens                                │
│  ▂▃▄▅▆▅▄▃▂ Refresh Tokens                               │
+─────────────────────────────────────────────────────────+
│  Authentication Success Rate                            │
│  Password:  92.5%  ████████████████████░░               │
│  Passkey:   98.7%  ███████████████████████              │
+─────────────────────────────────────────────────────────+
│  Top 10 Clients by Token Usage                          │
│  client_web_app:     1,245,678 tokens                   │
│  client_mobile_ios:    987,654 tokens                   │
│  client_mobile_android: 876,543 tokens                  │
+─────────────────────────────────────────────────────────+
```

**Dashboard 2: Security Events**

```
+─────────────────────────────────────────────────────────+
│  Security Event Timeline                                │
│  ▂▃▅█░ LOGIN                                            │
│  ░░▂▃░ FAILED_LOGIN                                     │
│  ░░░▂█ SUSPICIOUS_LOGIN                                 │
│  ░░░░▃ ACCOUNT_LOCKED                                   │
+─────────────────────────────────────────────────────────+
│  Password Integrity Violations (Last 24h)               │
│  Total: 3  ⚠️                                           │
│  - 2 from IP 203.0.113.45 (BLOCKED)                     │
│  - 1 from IP 198.51.100.23 (INVESTIGATING)              │
+─────────────────────────────────────────────────────────+
│  Unknown Device Detections                              │
│  ▂▃▄▅▆▇█ Rate: 12/hour                                  │
│  Top Countries: US (5), UK (3), DE (2), FR (2)          │
+─────────────────────────────────────────────────────────+
```

**Dashboard 3: Infrastructure Health**

```
+─────────────────────────────────────────────────────────+
│  ScyllaDB Performance                                   │
│  Write Latency (p99): 2.3ms  ████░░░░░                  │
│  Read Latency (p99):  0.8ms  ██░░░░░░░                  │
│  Compaction Lag:      12s    ██░░░░░░░                  │
+─────────────────────────────────────────────────────────+
│  Dragonfly Cache Hit Rate                               │
│  Hit Rate: 94.7%  ███████████████████░                  │
│  Evictions: 123/sec                                     │
+─────────────────────────────────────────────────────────+
│  Istio Circuit Breaker Status                           │
│  oauth2-service:      CLOSED ✅                         │
│  password-hasher:     CLOSED ✅                         │
│  passkey-service:     CLOSED ✅                         │
+─────────────────────────────────────────────────────────+
```

### Alerts

```yaml
# prometheus-alerts.yaml
groups:
- name: oauth2_alerts
  interval: 30s
  rules:
  
  # High error rate
  - alert: HighAuthFailureRate
    expr: |
      rate(oauth2_auth_attempts_total{result="failed"}[5m]) > 10
    for: 2m
    labels:
      severity: warning
    annotations:
      summary: "High authentication failure rate"
      description: "{{ $value }} failed auths/sec in the last 5 minutes"
  
  # Password integrity violation
  - alert: PasswordIntegrityViolation
    expr: |
      increase(security_integrity_violations_total{type="password"}[5m]) > 0
    for: 0m
    labels:
      severity: critical
    annotations:
      summary: "Database tampering detected!"
      description: "Password HMAC mismatch detected - possible database compromise"
  
  # Circuit breaker open
  - alert: CircuitBreakerOpen
    expr: |
      istio_requests_total{response_code="503"} > 0
    for: 1m
    labels:
      severity: warning
    annotations:
      summary: "Circuit breaker opened for {{ $labels.destination_service }}"
  
  # Vault unsealed
  - alert: VaultSealed
    expr: |
      vault_core_unsealed == 0
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: "Vault is sealed - service degraded"
  
  # ScyllaDB node down
  - alert: ScyllaDBNodeDown
    expr: |
      up{job="scylladb"} == 0
    for: 2m
    labels:
      severity: critical
    annotations:
      summary: "ScyllaDB node {{ $labels.instance }} is down"
```

### Distributed Tracing Example

```
Trace ID: a3f8c9d2e1b4f5a6

Span 1: POST /oauth2/token [200 OK] - 145ms
  │
  ├─► Span 2: Verify PKCE code_verifier - 2ms
  │
  ├─► Span 3: Fetch user from MongoDB - 12ms
  │
  ├─► Span 4: Verify password integrity (HMAC) - 3ms
  │     │
  │     └─► Span 5: Fetch HMAC key from Vault - 8ms
  │
  ├─► Span 6: gRPC call to password-hasher - 85ms
  │     │
  │     └─► Span 7: Argon2 verification - 78ms
  │
  ├─► Span 8: Generate JWT with Vault signing - 25ms
  │
  └─► Span 9: Store token in ScyllaDB - 18ms
```

---

## 🔐 Security Best Practices

### 1. Never Store Plaintext Secrets

❌ **Bad:**
```java
private static final String VAULT_TOKEN = "s.1234567890abcdef";
```

✅ **Good:**
```java
@Value("${vault.token}")
private String vaultToken;  // From Kubernetes secret

// Or use Vault Kubernetes auth
VaultTemplate vaultTemplate = new VaultTemplate(
    VaultEndpoint.from(vaultUri),
    new KubernetesAuthentication(
        "oauth2-service",  // Service account
        Paths.get("/var/run/secrets/kubernetes.io/serviceaccount/token")
    )
);
```

### 2. Rotate All Secrets Regularly

```bash
# Automated rotation with Vault
vault write auth/kubernetes/role/oauth2-service \
    bound_service_account_names=oauth2-service \
    bound_service_account_namespaces=default \
    policies=oauth2-policy \
    ttl=1h \
    max_ttl=24h

# Keys auto-rotate every 30 days
vault write transit/keys/oauth2-jwt-signing/rotate
```

### 3. Principle of Least Privilege

```yaml
# Kubernetes RBAC for OAuth2 service
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: oauth2-service-role
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["oauth2-config"]  # Only specific secret
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: oauth2-service-binding
subjects:
- kind: ServiceAccount
  name: oauth2-service
roleRef:
  kind: Role
  name: oauth2-service-role
  apiGroup: rbac.authorization.k8s.io
```

### 4. Network Segmentation

```yaml
# Istio AuthorizationPolicy - Only allow specific services
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: oauth2-access-control
spec:
  selector:
    matchLabels:
      app: oauth2-service
  action: ALLOW
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/default/sa/ingress-gateway"]
    to:
    - operation:
        methods: ["GET", "POST"]
        paths: ["/oauth2/*", "/api/webauthn/*"]
  
  - from:
    - source:
        principals: ["cluster.local/ns/default/sa/password-hasher"]
    to:
    - operation:
        methods: ["POST"]
        paths: ["/internal/verify-integrity"]
```

### 5. Audit Everything

```java
// Audit interceptor for all security events
@Component
public class SecurityAuditInterceptor implements HandlerInterceptor {
    
    @Autowired
    private KafkaTemplate<String, SecurityEvent> kafkaTemplate;
    
    @Override
    public void afterCompletion(HttpServletRequest request, 
                                HttpServletResponse response,
                                Object handler, Exception ex) {
        
        SecurityEvent event = SecurityEvent.builder()
            .user(getCurrentUserId())
            .event(determineEvent(request, response))
            .ipAddress(request.getRemoteAddr())
            .deviceHash(generateDeviceHash(request))
            .build();
        
        kafkaTemplate.send("security-events", event);
    }
}
```

---

## ⚡ Performance Tuning

### ScyllaDB Tuning

```cql
-- Enable bloom filter cache for faster lookups
ALTER TABLE access_tokens WITH bloom_filter_fp_chance = 0.01;

-- Tune compaction strategy
ALTER TABLE access_tokens WITH compaction = {
  'class': 'TimeWindowCompactionStrategy',
  'compaction_window_unit': 'HOURS',
  'compaction_window_size': 1
};

-- Set proper caching
ALTER TABLE access_tokens WITH caching = {
  'keys': 'ALL',
  'rows_per_partition': '100'
};
```

### Dragonfly Optimization

```yaml
# dragonfly.conf
maxmemory 8gb
maxmemory-policy allkeys-lru
save ""  # Disable persistence (session cache only)
appendonly no

# Enable pipelining for bulk operations
tcp-nodelay yes
tcp-backlog 511
```

### JVM Tuning

```bash
# OAuth2 service JVM flags
JAVA_OPTS="-Xms2g -Xmx4g \
  -XX:+UseG1GC \
  -XX:MaxGCPauseMillis=200 \
  -XX:+ParallelRefProcEnabled \
  -XX:+HeapDumpOnOutOfMemoryError \
  -XX:HeapDumpPath=/tmp/heapdump.hprof \
  -Dcom.sun.management.jmxremote \
  -Dcom.sun.management.jmxremote.port=9010 \
  -Dcom.sun.management.jmxremote.authenticate=false \
  -Dcom.sun.management.jmxremote.ssl=false"
```

### Istio Performance

```yaml
# Reduce latency with connection pooling
apiVersion: networking.istio.io/v1beta1
kind: DestinationRule
metadata:
  name: oauth2-performance
spec:
  host: oauth2-service
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 1000
        connectTimeout: 30ms
        tcpKeepalive:
          time: 7200s
          interval: 75s
      http:
        http2MaxRequests: 1000
        maxRequestsPerConnection: 10
        h2UpgradePolicy: UPGRADE
    loadBalancer:
      simple: LEAST_REQUEST  # Better than ROUND_ROBIN
```

---

## 🤝 Contributing

Contributions are welcome! This is a college project, but we encourage:

- Bug reports and fixes
- Performance improvements
- Documentation enhancements
- Security vulnerability reports

### Development Workflow

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_USERNAME/distributedSecurity.git
cd distributedSecurity

# 2. Create feature branch
git checkout -b feature/add-oauth2-device-flow

# 3. Make changes and test
./mvnw clean test
./mvnw verify

# 4. Run code quality checks
./mvnw sonar:sonar

# 5. Submit PR
git push origin feature/add-oauth2-device-flow
```

### Code Style

- Java: Google Java Style Guide
- Kotlin: Official Kotlin style guide
- Use `./mvnw spotless:apply` to format code

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Spring Security OAuth2** - Core authorization server framework
- **Yubico WebAuthn Java** - FIDO2/WebAuthn implementation
- **HashiCorp Vault** - Secrets management inspiration
- **ScyllaDB** - High-performance NoSQL database
- **Istio Community** - Service mesh best practices
- **Anthropic Claude** - README generation assistance 😊

---

## 📞 Contact

**Author:** Karan Kumar  
**GitHub:** [karankumar786786](https://github.com/karankumar786786)  
**Project Link:** [https://github.com/karankumar786786/distributedSecurity](https://github.com/karankumar786786/distributedSecurity)

---

## 🎓 Academic Note

This project was developed as a college project to demonstrate:
- Enterprise software architecture patterns
- OAuth2/OIDC implementation
- Cloud-native application design
- Security engineering principles
- DevOps and SRE practices

**Educational Objectives Met:**
- ✅ Distributed systems design
- ✅ Cryptographic protocol implementation
- ✅ Infrastructure as Code
- ✅ Observability and monitoring
- ✅ Security threat modeling

---

<div align="center">

**⭐ If this project helped you learn, please consider giving it a star! ⭐**

Made with ❤️ by [Karan Kumar](https://github.com/karankumar786786)

</div>