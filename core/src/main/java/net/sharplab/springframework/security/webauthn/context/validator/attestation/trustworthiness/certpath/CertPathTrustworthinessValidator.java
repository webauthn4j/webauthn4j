package net.sharplab.springframework.security.webauthn.context.validator.attestation.trustworthiness.certpath;

import net.sharplab.springframework.security.webauthn.anchor.WebAuthnTrustAnchorService;
import net.sharplab.springframework.security.webauthn.attestation.statement.FIDOU2FAttestationStatement;
import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;
import net.sharplab.springframework.security.webauthn.util.CertificateUtil;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.*;
import java.util.EnumSet;
import java.util.Set;

/**
 * Validates {@link CertPath} instance
 */
public interface CertPathTrustworthinessValidator{

    void validate(WebAuthnAttestationStatement attestationStatement);
}
