package net.sharplab.springframework.security.webauthn.anchor;

import java.security.cert.TrustAnchor;
import java.util.Set;

/**
 * Provides {@link TrustAnchor} set.
 */
public interface WebAuthnTrustAnchorService {

    /**
     * Provides {@link TrustAnchor} set.
     * @return {@link TrustAnchor} set.
     */
    Set<TrustAnchor> getTrustAnchors();
}
