package net.sharplab.springframework.security.webauthn.anchor;

import org.springframework.core.io.Resource;

import java.security.cert.TrustAnchor;
import java.util.Set;

/**
 * KeyStore backed TrustAnchorService
 * Load a key store at first time access and cache it.
 */
public class KeyStoreTrustAnchorService implements WebAuthnTrustAnchorService {

    private Resource keyStore;
    private String password;

    private Set<TrustAnchor> cachedTrustAnchors;

    /**
     * Default constructor
     */
    public KeyStoreTrustAnchorService(){
        KeyStoreTrustAnchorProvider keyStoreTrustAnchorProvider = new KeyStoreTrustAnchorProvider();
        this.cachedTrustAnchors = keyStoreTrustAnchorProvider.provide(keyStore, password);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Set<TrustAnchor> getTrustAnchors() {
        return cachedTrustAnchors;
    }

    /**
     * Provides keyStore file resource
     * @return keyStore file resource
     */
    public Resource getKeyStore() {
        return keyStore;
    }

    /**
     * Sets keyStore file resource
     * @param keyStore keyStore file resource
     */
    public void setKeyStore(Resource keyStore) {
        this.keyStore = keyStore;
    }

    /**
     * Provides keyStore file password
     * @return keyStore file password
     */
    public String getPassword() {
        return password;
    }

    /**
     * Sets keyStore file password
     * @param password keyStore file password
     */
    public void setPassword(String password) {
        this.password = password;
    }
}
