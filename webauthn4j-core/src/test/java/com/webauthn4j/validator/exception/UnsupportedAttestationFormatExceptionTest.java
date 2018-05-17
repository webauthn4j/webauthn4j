package com.webauthn4j.validator.exception;

import org.junit.Test;

@SuppressWarnings("ThrowableNotThrown")
public class UnsupportedAttestationFormatExceptionTest {

    private RuntimeException cause = new RuntimeException();

    @Test
    public void test() {
        new UnsupportedAttestationFormatException("dummy");
        new UnsupportedAttestationFormatException("dummy", cause);
    }
}
