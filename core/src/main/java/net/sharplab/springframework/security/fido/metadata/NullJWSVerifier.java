package net.sharplab.springframework.security.fido.metadata;

import com.nimbusds.jose.JWSObject;

/**
 * A JWSVerifier but does nothing
 */
public class NullJWSVerifier implements JWSVerifier {

    /**
     * {@inheritDoc}
     */
    @Override
    public void verify(JWSObject jws) {
        //nop
    }
}
