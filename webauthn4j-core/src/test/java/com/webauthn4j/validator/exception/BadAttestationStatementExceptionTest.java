package com.webauthn4j.validator.exception;

import org.junit.Test;

@SuppressWarnings("ThrowableNotThrown")
public class BadAttestationStatementExceptionTest {

    private RuntimeException cause = new RuntimeException();

    @Test
    public void test(){
        new BadAttestationStatementException("dummy");
        new BadAttestationStatementException("dummy", cause);
    }
}
