package com.webauthn4j.anchor;

import com.webauthn4j.exception.KeyStoreException;
import org.junit.Test;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.TrustAnchor;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

public class KeyStoreTrustAnchorProviderImplTest {

    private KeyStoreTrustAnchorProviderImpl target;

    @Test
    public void provide_test() throws Exception{
        target = new KeyStoreTrustAnchorProviderImpl();
        Path path = Paths.get(ClassLoader.getSystemResource("attestation/jks/ssw-test.jks").toURI());
        target.setKeyStore(path);
        target.setPassword("password");

        Set<TrustAnchor> trustAnchors = target.provide();
        assertThat(trustAnchors).isNotEmpty();
    }

    @Test(expected = KeyStoreException.class)
    public void provide_test_with_invalid_path() throws Exception{
        target = new KeyStoreTrustAnchorProviderImpl();
        Path path = Paths.get("invalid.path.to.jks");
        target.setKeyStore(path);
        target.setPassword("password");

        target.provide();
    }

}
