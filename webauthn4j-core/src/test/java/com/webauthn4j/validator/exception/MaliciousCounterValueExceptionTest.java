package com.webauthn4j.validator.exception;

import org.junit.Test;

@SuppressWarnings("ThrowableNotThrown")
public class MaliciousCounterValueExceptionTest {

    private RuntimeException cause = new RuntimeException();

    @Test
    public void test(){
        new MaliciousCounterValueException("dummy");
        new MaliciousCounterValueException("dummy", cause);
    }
}
