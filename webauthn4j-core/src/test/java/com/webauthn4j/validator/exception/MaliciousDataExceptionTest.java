package com.webauthn4j.validator.exception;

import org.junit.Test;

@SuppressWarnings("ThrowableNotThrown")
public class MaliciousDataExceptionTest {

    private RuntimeException cause = new RuntimeException();

    @Test
    public void test(){
        new MaliciousDataException("dummy");
        new MaliciousDataException("dummy", cause);
    }
}
