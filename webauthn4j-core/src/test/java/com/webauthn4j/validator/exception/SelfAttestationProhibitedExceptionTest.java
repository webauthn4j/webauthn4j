package com.webauthn4j.validator.exception;

import org.junit.Test;

@SuppressWarnings("ThrowableNotThrown")
public class SelfAttestationProhibitedExceptionTest {

    private RuntimeException cause = new RuntimeException();

    @Test
    public void test() {
        new SelfAttestationProhibitedException("dummy");
        new SelfAttestationProhibitedException("dummy", cause);
    }
}
