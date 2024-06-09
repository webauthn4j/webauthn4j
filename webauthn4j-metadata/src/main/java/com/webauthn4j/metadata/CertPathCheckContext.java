package com.webauthn4j.metadata;

import java.security.cert.CertPath;
import java.security.cert.TrustAnchor;
import java.util.Set;

public class CertPathCheckContext {

    private final CertPath certPath;
    private final Set<TrustAnchor> trustAnchors;
    private final boolean revocationCheckEnabled;

    public CertPathCheckContext(CertPath certPath, Set<TrustAnchor> trustAnchors, boolean revocationCheckEnabled) {
        this.certPath = certPath;
        this.trustAnchors = trustAnchors;
        this.revocationCheckEnabled = revocationCheckEnabled;
    }

    public CertPath getCertPath() {
        return certPath;
    }

    public Set<TrustAnchor> getTrustAnchors() {
        return trustAnchors;
    }

    public boolean isRevocationCheckEnabled() {
        return revocationCheckEnabled;
    }
}