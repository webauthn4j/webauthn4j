package com.webauthn4j.async.verifier.attestation.trustworthiness.self;

import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;

import java.util.concurrent.CompletionStage;

/**
 * Verifies the specified {@link AttestationStatement} trustworthiness based on self-attestation rule
 */
public interface SelfAttestationTrustworthinessAsyncVerifier {
    CompletionStage<Void> verify(CertificateBaseAttestationStatement certificateBaseAttestationStatement);
}
