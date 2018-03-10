package net.sharplab.springframework.security.webauthn.client.challenge;

import java.io.Serializable;

public interface Challenge extends Serializable {

    /**
     * Gets the challenge value. Cannot be null.
     *
     * @return the challenge value
     */
    byte[] getValue();

}
