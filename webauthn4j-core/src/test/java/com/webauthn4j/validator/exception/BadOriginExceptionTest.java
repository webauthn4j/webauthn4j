package com.webauthn4j.validator.exception;

import org.junit.Test;

@SuppressWarnings("ThrowableNotThrown")
public class BadOriginExceptionTest {

    private RuntimeException cause = new RuntimeException();

    @Test
    public void test(){
        new BadOriginException("dummy");
        new BadOriginException("dummy", cause);
    }
}
