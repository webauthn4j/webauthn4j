package net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.ecdaa;

import net.sharplab.springframework.security.webauthn.anchor.WebAuthnTrustAnchorService;
import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;

/**
 * Validates {@link WebAuthnAttestationStatement} based on ECDAA
 */
public interface ECDAATrustworthinessValidator {

    void validate(WebAuthnAttestationStatement attestationStatement);
}
