package com.webauthn4j.reactive.verifier.attestation.trustworthiness.certpath;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;

import java.time.Instant;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

public class NullCertPathTrustworthinessReactiveVerifier implements CertPathTrustworthinessReactiveVerifier {
    @Override
    public CompletionStage<Void> verify(AAGUID aaguid, CertificateBaseAttestationStatement certificateBaseAttestationStatement, Instant timestamp) {
        return CompletableFuture.completedFuture(null);
    }
}
