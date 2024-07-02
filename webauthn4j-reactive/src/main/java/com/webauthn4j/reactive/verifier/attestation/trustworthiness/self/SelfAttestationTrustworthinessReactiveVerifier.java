package com.webauthn4j.reactive.verifier.attestation.trustworthiness.self;

import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;

import java.util.concurrent.CompletionStage;

public interface SelfAttestationTrustworthinessReactiveVerifier {
    CompletionStage<Void> verify(CertificateBaseAttestationStatement certificateBaseAttestationStatement);
}
