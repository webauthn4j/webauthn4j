package com.webauthn4j.validator.assertion.signature;

import com.webauthn4j.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.WebAuthnAuthenticationContext;

public interface AssertionSignatureValidator {

    void verifySignature(WebAuthnAuthenticationContext webAuthnAuthenticationContext, CredentialPublicKey credentialPublicKey);

}
