package net.sharplab.springframework.security.webauthn.anchor;

import net.sharplab.springframework.security.webauthn.exception.CertificateException;
import net.sharplab.springframework.security.webauthn.exception.KeyStoreLoadException;
import net.sharplab.springframework.security.webauthn.util.CertificateUtil;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.io.Resource;
import org.springframework.security.core.SpringSecurityMessageSource;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Provides {@link TrustAnchor}'{@link Set} backed by Java KeyStore file.
 */
public class KeyStoreTrustAnchorProvider {

    //~ Instance fields ================================================================================================
    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    /**
     * Provides {@link TrustAnchor}'{@link Set} backed by Java KeyStore file.
     * @param keyStoreResource KeyStore file resource
     * @param password KeyStore file password
     * @return {@link TrustAnchor}'{@link Set}
     */
    public Set<TrustAnchor> provide(Resource keyStoreResource, String password) {
        KeyStore keyStore = loadKeyStoreFromResource(keyStoreResource, password);
        try {
            List<String> aliases = Collections.list(keyStore.aliases());
            Set<TrustAnchor> trustAnchors = new HashSet<>();
            for (String alias: aliases ) {
                X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
                trustAnchors.add(new TrustAnchor(certificate, null)); //TODO: null?
            }
            return trustAnchors;
        } catch (KeyStoreException e) {
            throw new KeyStoreLoadException(messages.getMessage("KeyStoreTrustAnchorProvider.ioError",
                    "Certificate load error"), e);
        }
    }

    private KeyStore loadKeyStoreFromResource(Resource keyStoreResource, String password){
        KeyStore keyStore = CertificateUtil.generateKeyStore();
        try {
            keyStore.load(keyStoreResource.getInputStream(), password.toCharArray());
        } catch (IOException e) {
            throw new KeyStoreLoadException(messages.getMessage("KeyStoreTrustAnchorProvider.ioError",
                    "IO Error"), e);
        } catch (NoSuchAlgorithmException e) {
            throw new KeyStoreLoadException(messages.getMessage("KeyStoreTrustAnchorProvider.noSuchAlgorithm",
                    "No such algorithm"), e);
        } catch (java.security.cert.CertificateException e) {
            throw new CertificateException(messages.getMessage("KeyStoreTrustAnchorProvider.certificateValidationFailed",
                    "Certificate validation failed"), e);
        }
        return keyStore;
    }
}
