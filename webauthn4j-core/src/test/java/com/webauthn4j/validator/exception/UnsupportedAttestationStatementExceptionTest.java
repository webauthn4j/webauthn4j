package com.webauthn4j.validator.exception;

import org.junit.Test;

@SuppressWarnings("ThrowableNotThrown")
public class UnsupportedAttestationStatementExceptionTest {

    private RuntimeException cause = new RuntimeException();

    @Test
    public void test(){
        new UnsupportedAttestationStatementException("dummy");
        new UnsupportedAttestationStatementException("dummy", cause);
    }
}
