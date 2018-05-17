package com.webauthn4j.validator.exception;

import org.junit.Test;

@SuppressWarnings("ThrowableNotThrown")
public class BadRpIdExceptionTest {

    private RuntimeException cause = new RuntimeException();

    @Test
    public void test() {
        new BadRpIdException("dummy");
        new BadRpIdException("dummy", cause);
    }
}
