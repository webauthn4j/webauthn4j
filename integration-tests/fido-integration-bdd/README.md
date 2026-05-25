# FIDO Integration BDD Tests

## System Under Test

This test suite verifies the integration of three components across the
FIDO2/WebAuthn protocol stack:

```
┌─────────────────────────────────────────────────────────────┐
│  Server (Relying Party)                                     │
│  webauthn4j-core: WebAuthnManager                           │
│  - Verifies registration (attestation, client data)         │
│  - Verifies authentication (signature, authenticator data)  │
│  - Stores credentials (credential store)                    │
└──────────────────────────┬──────────────────────────────────┘
                           │  RegistrationRequest / AuthenticationRequest
┌──────────────────────────┴──────────────────────────────────┐
│  Client Platform                                            │
│  webauthn4j-ctap: WebAuthnClient                            │
│  - Filters authenticators by attachment                     │
│  - Handles attestation conveyance preference                │
│  - Sets origin in CollectedClientData                       │
│  - Provides client PIN to authenticator                     │
│  - Manages credential selection for discoverable credentials│
└──────────────────────────┬──────────────────────────────────┘
                           │  CTAP2 protocol (InProcessAdaptor)
┌──────────────────────────┴──────────────────────────────────┐
│  Authenticator                                              │
│  webauthn4j-ctap: CtapAuthenticator                         │
│  - Generates credentials (makeCredential)                   │
│  - Signs assertions (getAssertion)                          │
│  - Manages client PIN, reset                                │
└─────────────────────────────────────────────────────────────┘
```

## DSL

Test environments are set up declaratively. All components (clientPlatform,
authenticator, relyingParty) must be explicitly declared:

```kotlin
// Standard: single authenticator with custom settings
val env = WebAuthnTestEnvironment.create {
    clientPlatform {
        authenticator { algorithms = setOf(ES256) }
    }
    relyingParty { rpId = "example.com" }
}

// Multiple authenticators on one client platform
val env = WebAuthnTestEnvironment.create {
    clientPlatform {
        authenticator { attachment = CROSS_PLATFORM }
        authenticator { attachment = PLATFORM }
    }
    relyingParty()
}

// All defaults (ES256, CROSS_PLATFORM, example.com)
val env = WebAuthnTestEnvironment.createDefault()
```

### Protocol flows via step objects

Registration and authentication flows are decomposed into step objects,
each representing a protocol state:

```kotlin
// Full chain
val result = env.scenario
    .createRegistrationOptions()
    .createCredential()
    .verifyOnServer()

// Step-by-step with inspection
val options = env.scenario.createRegistrationOptions(pubKeyCredParams = listOf(...))
val credentialCreated = options.createCredential()
val result = credentialCreated.verifyOnServer(rpId = "...")

// Convenience (all defaults)
env.scenario.register()
env.scenario.authenticate()
```

### Accessing components

```kotlin
env.relyingParty.webAuthnManager   // Server verification
env.clientPlatform.webAuthnClient  // Client Platform
env.clientPlatform.ctapService     // CTAP service (PIN, reset, etc.)
```

## Test Design

### Component Parameters

Each component has configurable parameters. Tests verify behavior when
these parameters are varied individually or in combination.
Server parameters are listed first as webauthn4j is a server-side library.

**Server parameters:**

*PublicKeyCredentialCreationOptions (Registration request):*

| Parameter | Values |
|-----------|--------|
| `rp` (rpId, rpName) | RP identifier and display name |
| `user` (id, name, displayName) | User entity |
| `challenge` | Random challenge |
| `pubKeyCredParams` | Algorithm list |
| `timeout` | Milliseconds (optional) |
| `excludeCredentials` | Credential ID list |
| `authenticatorSelection.authenticatorAttachment` | PLATFORM, CROSS_PLATFORM, null |
| `authenticatorSelection.residentKey` | REQUIRED, PREFERRED, DISCOURAGED |
| `authenticatorSelection.userVerification` | REQUIRED, PREFERRED, DISCOURAGED |
| `attestation` | DIRECT, NONE, INDIRECT, ENTERPRISE |
| `attestationFormats` | Requested attestation format list |
| `hints` | PUBLIC_KEY, CLIENT_DEVICE, SECURITY_KEY |
| `extensions` | WebAuthn extensions (credProtect, uvm, credProps, hmacCreateSecret, ...) |

*PublicKeyCredentialRequestOptions (Authentication request):*

| Parameter | Values |
|-----------|--------|
| `challenge` | Random challenge |
| `timeout` | Milliseconds (optional) |
| `rpId` | RP identifier |
| `allowCredentials` | Credential ID list |
| `userVerification` | REQUIRED, PREFERRED, DISCOURAGED |
| `hints` | PUBLIC_KEY, CLIENT_DEVICE, SECURITY_KEY |
| `extensions` | WebAuthn extensions (appid, appidExclude, uvm, hmacGetSecret, ...) |

*ServerProperty (Verification):*

| Parameter | Values |
|-----------|--------|
| `origin` / `originPredicate` | Expected origin(s) for verification |
| `topOrigin` / `topOriginPredicate` | Expected top-level origin for cross-origin iframe |
| `rpId` | RP identifier for rpIdHash verification |
| `challenge` | Expected challenge |

*RegistrationParameters (Registration verification flags):*

| Parameter | Values |
|-----------|--------|
| `userVerificationRequired` | true, false |
| `userPresenceRequired` | true, false |
| `pubKeyCredParams` | Allowed algorithms for verification |

*AuthenticationParameters (Authentication verification flags):*

| Parameter | Values |
|-----------|--------|
| `userVerificationRequired` | true, false |
| `userPresenceRequired` | true, false |
| `allowCredentials` | Allowed credential IDs for verification |
| `signatureCounter` validation | Counter must increment |

**Client Platform parameters:**

| Parameter | Values |
|-----------|--------|
| `origin` | URL (set in CollectedClientData) |
| `crossOrigin` | true, false (cross-origin iframe context) |
| `topOrigin` | Top-level origin (set when crossOrigin=true) |
| Attestation conveyance handling | DIRECT, NONE, INDIRECT processing |
| Authenticator filtering | Filter by attachment type |
| Credential selection handler | Select from discoverable credentials |
| Client PIN provider | Provides PIN value |

**Authenticator parameters:**

| Parameter | Values |
|-----------|--------|
| `attestationStatementProvider` | Packed, FIDO U2F, None |
| `algorithms` | ES256, RS256, ... |
| `residentKey` | ALWAYS, IF_REQUIRED, NEVER |
| `userVerification` | READY, NOT_READY, NOT_SUPPORTED |
| `userPresence` | SUPPORTED, NOT_SUPPORTED |
| `attachment` | PLATFORM, CROSS_PLATFORM |
| `aaguid` | Custom UUID |
| `credentialSelector` | CLIENT_PLATFORM, AUTHENTICATOR |
| `clientPIN` | ENABLED, DISABLED |
| `resetProtection` | ENABLED, DISABLED |
| `transports` | USB, NFC, BLE, INTERNAL, HYBRID |

### Parameter Interaction Map

Not all parameters interact. Tests are needed only for parameters that
affect each other's behavior. Independent parameters are tested in
isolation. The map is organized around what the Server requests or
verifies, since server-side verification is the primary concern.

| Classification | Server | Client Platform | Authenticator | Interaction |
|---|---|---|---|---|
| | **— Credential —** | | | |
| Matrix | `pubKeyCredParams` | — | `algorithms` | Algorithm negotiation |
| Matrix | `residentKeyRequirement` | — | `residentKey` | Resident key negotiation |
| Matrix | `excludeCredentials` | — | — | Exclude check |
| Matrix | — | selection handler | `credentialSelector` | Credential selection |
| | **— User Verification —** | | | |
| Matrix | `userVerificationRequirement` | PIN provider | `userVerification`, `clientPIN` | UV negotiation |
| Matrix | `userPresenceRequired` | — | `userPresence` | UP validation |
| | **— Authenticator Selection —** | | | |
| Matrix | `authenticatorAttachment` | **filtering** | `attachment` | Attachment matching |
| | **— Attestation —** | | | |
| Matrix | `attestation` preference | **conveyance handling** | `attestationProvider` | Attestation delivery |
| Matrix | AttestationStatementVerifier, TrustAnchorRepository | — | `attestationProvider` | Attestation trust verification |
| | **— Server Verification —** | | | |
| Matrix | `origin` (ServerProperty) | `origin` | — | Origin validation |
| Matrix | `topOrigin` (ServerProperty) | `crossOrigin`, `topOrigin` | — | Cross-origin validation |
| Matrix | `rpId` (ServerProperty) | — | — | RP ID validation |
| Matrix | `challenge` (ServerProperty) | — | — | Challenge validation |
| Matrix | counter validation | — | — | Signature counter |
| Single | — | — | `aaguid` | Authenticator identity: propagated as-is, no interaction |
| Single | — | — | `resetProtection` | Authenticator management: independent setting |
| Single | — | — | `transports` | Transport hints: propagated to credential record, no negotiation |
| | **— Out of Scope —** | | | |
| Out of scope | `timeout` | — | — | Not implemented in webauthn4j-ctap |
| Out of scope | `hints` | — | — | Advisory only, no behavioral impact |
| Out of scope | `attestationFormats` | — | — | Not implemented in webauthn4j-ctap |
| Out of scope | `extensions` | — | — | Per-extension testing; separate effort |
| Out of scope | `user` (id, name, displayName) | — | — | Passed through; server doesn't verify |
| Out of scope | `rp.name` | — | — | Display only; server doesn't verify |

## Test Categories

Based on the interaction map, tests are organized into:

### 1. Parameter Tests

Tests that vary one or more parameters and verify their effect on the
registration/authentication flow. Covers both single-parameter and
cross-component interaction (matrix) cases.

| Group | Test | Parameters | Spec |
|-------|------|-----------|------|
| Credential | Algorithm negotiation (client) | Server.`pubKeyCredParams` × Authenticator.`algorithms` | `AlgorithmSpec` |
| Credential | Algorithm verification (server) | Authenticator.`algorithms` × Server.`RegistrationParameters.pubKeyCredParams` | `AlgorithmSpec` |
| Credential | Resident key negotiation | Server.`residentKeyRequirement` × Authenticator.`residentKey` | `ResidentKeySpec` |
| Credential | Exclude credentials | Server.`excludeCredentials` | `ExcludeCredentialsSpec` |
| Credential | Allow credentials | Server.`allowCredentials` | `AllowCredentialsSpec` |
| Credential | Credential selection | Client.selectionHandler × Authenticator.`credentialSelector` | `CredentialSelectorSpec` |
| User Verification | UV negotiation | Server.`userVerificationRequirement` × Authenticator.`userVerification` × Authenticator.`clientPIN` | `UserVerificationSpec` |
| User Verification | ClientPIN impact | Authenticator.`clientPIN` × Authenticator.`userVerification` | `ClientPINSpec` |
| User Verification | UP validation | Server.`userPresenceRequired` × Authenticator.`userPresence` | `UserPresenceSpec` |
| Authenticator Selection | Attachment matching | Server.`authenticatorAttachment` × Client.filtering × Authenticator.`attachment` | `AttachmentSpec` |
| Attestation | Attestation delivery | Server.`attestation` × Client.conveyance × Authenticator.`attestationProvider` | `AttestationConveyanceSpec`, `AttestationFormatSpec` |
| Attestation | Attestation trust | Server.AttestationStatementVerifier, TrustAnchorRepository × Authenticator.`attestationProvider` | `AttestationTrustSpec` |
| Server Verification | Origin validation | Server.`origin` × Client.`origin` | `OriginSpec` |
| Server Verification | Cross-origin validation | Server.`topOrigin` × Client.`crossOrigin`, `topOrigin` | `CrossOriginSpec` (@Ignored) |
| Server Verification | RP ID validation | Server.`rpId` | `RpIdSpec` |
| Server Verification | Challenge validation | Server.`challenge` | `ChallengeSpec` |
| Server Verification | Signature counter | Server.counter check | `CounterSpec` |
| Server Verification | Backup state | BE/BS flag consistency | `BackupStateSpec` |
| Server Verification | Credential ID | ID length ≤1023, uniqueness | `CredentialIdSpec` |
| Authenticator | AAGUID propagation | Authenticator.`aaguid` | `AAGUIDSpec` |
| Authenticator | Reset protection | Authenticator.`resetProtection` | `ResetProtectionSpec` |
| Authenticator | Transport hints | Authenticator.`transports` | `TransportSpec` |

### 2. Scenario Tests

End-to-end tests that verify complete user journeys spanning multiple
protocol operations.

| Scenario | Description | Spec |
|----------|-------------|------|
| Passwordless flow | Resident key registration → discoverable authentication | `PasswordlessFlowSpec` |
| Second factor flow | Non-resident registration → allowCredentials authentication | `SecondFactorFlowSpec` |
| Client PIN management | PIN set, change, retry count | `ClientPINManagementSpec` |
| Credential deletion | Delete credential → authentication fails | `CredentialDeletionSpec` |

## Architecture

### Package Structure

```
environment/
├── Authenticator.kt            — Authenticator.Builder + Authenticator (InternalTransport)
├── ClientPlatform.kt           — ClientPlatform (WebAuthnClient, CtapService)
├── RelyingParty.kt             — RelyingParty.Builder + RelyingParty (WebAuthnManager, credential store)
├── StandardScenario.kt         — Protocol flow orchestration + step objects + result classes
└── WebAuthnTestEnvironment.kt  — WebAuthnTestEnvironment.create/createDefault + EnvironmentDsl + ClientPlatformDsl

support/
└── BddHtmlReporter.kt          — Custom single-page BDD HTML report with @Tags grouping
```

### Step Objects (in StandardScenario)

Registration flow:
```
createRegistrationOptions() → RegistrationOptionsCreated
    .createCredential()     → RegistrationCredentialCreated
    .verifyOnServer()       → RegistrationResult
```

Authentication flow:
```
createAuthenticationOptions() → AuthenticationOptionsCreated
    .getAssertion()           → AuthenticationAssertionCreated
    .verifyOnServer()         → AuthenticationResult
```

## Running Tests

```bash
# Run all tests
./gradlew :integration-tests:fido-integration-bdd:test

# BDD HTML report
# Generated at: build/reports/bdd/index.html
```
