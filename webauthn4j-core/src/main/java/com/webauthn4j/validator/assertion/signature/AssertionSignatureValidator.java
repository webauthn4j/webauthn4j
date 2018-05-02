package com.webauthn4j.validator.assertion.signature;

import com.webauthn4j.WebAuthnAuthenticationContext;
import com.webauthn4j.attestation.authenticator.CredentialPublicKey;

public interface AssertionSignatureValidator {

    void verifySignature(WebAuthnAuthenticationContext webAuthnAuthenticationContext, CredentialPublicKey credentialPublicKey);

}
