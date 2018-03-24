package com.webauthn4j.webauthn.context.validator.assertion.signature;

import com.webauthn4j.webauthn.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.webauthn.context.WebAuthnAuthenticationContext;

public interface AssertionSignatureValidator {

    void verifySignature(WebAuthnAuthenticationContext webAuthnAuthenticationContext, CredentialPublicKey credentialPublicKey);

}
