package com.webauthn4j.validator.exception;

import org.junit.Test;

@SuppressWarnings("ThrowableNotThrown")
public class BadSignatureExceptionTest {

    private RuntimeException cause = new RuntimeException();

    @Test
    public void test() {
        new BadSignatureException("dummy");
        new BadSignatureException("dummy", cause);
    }
}
