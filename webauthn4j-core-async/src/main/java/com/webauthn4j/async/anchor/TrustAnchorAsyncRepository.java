package com.webauthn4j.async.anchor;

import com.webauthn4j.data.attestation.authenticator.AAGUID;

import java.security.cert.TrustAnchor;
import java.util.Set;
import java.util.concurrent.CompletionStage;

/**
 * Repository interface that look up {@link TrustAnchor}(s)
 * WebAuthn4J uses this interface to lookup {@link TrustAnchor}(s) for an attestation certificate when verifying the authenticator.
 */
public interface TrustAnchorAsyncRepository {

    /**
     * Look up {@link TrustAnchor}(s) by {@link AAGUID}
     * @param aaguid {@link AAGUID} for the authenticator
     * @return {@link CompletionStage<Set<TrustAnchor>>}
     */
    CompletionStage<Set<TrustAnchor>> find(AAGUID aaguid);

    /**
     * Look up {@link TrustAnchor}(s) by attestationCertificateKeyIdentifier. This is used for FIDO-U2F authenticator
     * @param attestationCertificateKeyIdentifier attestationCertificateKeyIdentifier for the authenticator
     * @return {@link CompletionStage<Set<TrustAnchor>>}
     */
    CompletionStage<Set<TrustAnchor>> find(byte[] attestationCertificateKeyIdentifier);
}
