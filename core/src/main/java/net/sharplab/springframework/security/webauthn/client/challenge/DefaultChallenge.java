package net.sharplab.springframework.security.webauthn.client.challenge;

import org.springframework.util.Assert;

public class DefaultChallenge implements Challenge {
    private final byte[] value;

    /**
     * Creates a new instance
     *
     * @param value the value of the challenge
     */
    public DefaultChallenge(byte[] value) {
        Assert.notNull(value, "value cannot be null or empty");
        this.value = value;
    }

    @Override
    public byte[] getValue() {
        return this.value;
    }
}
