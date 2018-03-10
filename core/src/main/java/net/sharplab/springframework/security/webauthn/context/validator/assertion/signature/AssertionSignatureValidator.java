package net.sharplab.springframework.security.webauthn.context.validator.assertion.signature;

import net.sharplab.springframework.security.webauthn.attestation.authenticator.AbstractCredentialPublicKey;
import net.sharplab.springframework.security.webauthn.context.WebAuthnAuthenticationContext;

/**
 * AbstractAssertionSignatureValidator
 */
public interface AssertionSignatureValidator {

    void verifySignature(WebAuthnAuthenticationContext webAuthnAuthenticationContext, AbstractCredentialPublicKey credentialPublicKey);

    boolean supports(String format);
}
