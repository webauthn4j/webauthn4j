package com.webauthn4j.context.validator.assertion.signature;

import com.webauthn4j.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.context.WebAuthnAuthenticationContext;

public interface AssertionSignatureValidator {

    void verifySignature(WebAuthnAuthenticationContext webAuthnAuthenticationContext, CredentialPublicKey credentialPublicKey);

}
