# SPC E2E Test

End-to-end test for Secure Payment Confirmation (SPC) using Selenium + Quarkus.

## Components

| File | Role |
|---|---|
| `SPCResource.java` | Quarkus REST API. Plays both RP and Merchant roles in a single server |
| `register.html` | Registration page (served on `bank.localhost`) |
| `pay.html` | Payment page (served on `merchant.localhost`) |
| `SPCEndToEndTest.java` | E2E test using Selenium + ChromeDriver |

## Test Flow

### Setup

1. Launch ChromeDriver in headless mode
2. Add a virtual authenticator (CTAP2, platform, user verification enabled)
3. Set SPC Transaction Mode to `autoAccept` via WebDriver extension command
   (`POST /session/{id}/secure-payment-confirmation/set-mode`, per SPC spec §10.1)

### Test Scenario (`testSPCCrossOriginRegistrationAndAuthentication`)

**Registration (on `bank.localhost`)**

1. Navigate to `register.html`
2. Click the register button
3. Frontend fetches `PublicKeyCredentialCreationOptions` (with `payment` extension) from `/api/register/options`
4. Call `navigator.credentials.create()` to create a credential
5. Send the result to `/api/register/verify`, which calls `SPCManager.verify()`
6. Server stores `CredentialRecord` and `credentialId`

**Authentication (on `merchant.localhost`) — cross-origin**

1. Navigate to `pay.html` (the credential was registered on `bank.localhost`)
2. Click the pay button
3. Frontend fetches `SecurePaymentConfirmationRequest` from `/api/authenticate/options`
4. Call `PaymentRequest` API with `secure-payment-confirmation` method (auto-accepted by the virtual authenticator)
5. Send the assertion to `/api/authenticate/verify`, which calls `SPCManager.verify()`
6. `ServerProperty.origin` is set to the **merchant's origin** (`http://merchant.localhost:8080`), demonstrating SPC's cross-origin capability

## Simplifications

In a real SPC deployment, the Relying Party (e.g., a bank) and the Merchant
are separate servers. The Merchant requests a challenge and credential IDs
from the RP before authentication, and forwards the assertion back to the RP
for verification.

This test simplifies the architecture in several ways:

- **Single server**: A single Quarkus server plays both RP and Merchant roles.
  In production, the Merchant and RP communicate out-of-band (e.g., via 3D
  Secure) to exchange challenge/credentialIds and forward assertions. This
  inter-server communication is skipped; the server handles everything
  internally.
- **No session-based challenge storage**: Challenges are stored in an instance
  field rather than in a proper session store. In production, challenges should
  be stored in a session and validated to prevent replay attacks.
- **HTTP with `*.localhost`**: Chrome treats `*.localhost` as a secure context,
  so HTTPS is not required.
- **`payeeOrigin` vs `ServerProperty.origin`**: `payeeOrigin` is set to
  `https://merchant.localhost` (SPC spec requires HTTPS), while
  `ServerProperty.origin` is `http://merchant.localhost:8080` (actual browser
  origin).

## Platform Limitation

SPC is only supported on Chrome for Windows and macOS.
The test is annotated with `@EnabledOnOs({OS.WINDOWS, OS.MAC})`.
