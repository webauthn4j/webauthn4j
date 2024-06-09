package com.webauthn4j.async.verifier.attestation.trustworthiness.self;

import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;

import java.util.concurrent.CompletionStage;

public interface SelfAttestationTrustworthinessAsyncVerifier {
    CompletionStage<Void> verify(CertificateBaseAttestationStatement certificateBaseAttestationStatement);
}
