package net.sharplab.springframework.security.fido.metadata;

import com.nimbusds.jose.JWSObject;

/**
 * Verifier for JWS (Json Web Signature)
 */
public interface JWSVerifier {

    /**
     * Verify {@link JWSObject}
     * @param jws verification target
     */
    void verify(JWSObject jws);
}
