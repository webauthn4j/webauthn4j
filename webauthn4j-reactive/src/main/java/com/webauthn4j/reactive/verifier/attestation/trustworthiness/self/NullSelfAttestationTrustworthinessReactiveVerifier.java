package com.webauthn4j.reactive.verifier.attestation.trustworthiness.self;

import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

public class NullSelfAttestationTrustworthinessReactiveVerifier implements SelfAttestationTrustworthinessReactiveVerifier{
    @Override
    public CompletionStage<Void> verify(CertificateBaseAttestationStatement certificateBaseAttestationStatement) {
        //nop
        return CompletableFuture.completedFuture(null);
    }
}
