package com.webauthn4j.async.anchor;

import com.webauthn4j.data.attestation.authenticator.AAGUID;

import java.security.cert.TrustAnchor;
import java.util.Set;
import java.util.concurrent.CompletionStage;

public interface TrustAnchorAsyncRepository {

    CompletionStage<Set<TrustAnchor>> find(AAGUID aaguid);
    CompletionStage<Set<TrustAnchor>> find(byte[] attestationCertificateKeyIdentifier);
}
