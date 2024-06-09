package com.webauthn4j.async.verifier.attestation.trustworthiness.certpath;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;

import java.time.Instant;
import java.util.concurrent.CompletionStage;

public interface CertPathTrustworthinessAsyncVerifier {
    CompletionStage<Void> verify(AAGUID aaguid, CertificateBaseAttestationStatement certificateBaseAttestationStatement, Instant timestamp);
}
