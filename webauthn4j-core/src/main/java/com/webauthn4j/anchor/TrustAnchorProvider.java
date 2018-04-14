package com.webauthn4j.anchor;

import java.security.cert.TrustAnchor;
import java.util.Set;

/**
 * Provides {@link TrustAnchor}'{@link Set}.
 */
public interface TrustAnchorProvider {

    /**
     * Provides {@link TrustAnchor}'{@link Set}.
     *
     * @return {@link TrustAnchor}'{@link Set}
     */
    Set<TrustAnchor> provide();
}
