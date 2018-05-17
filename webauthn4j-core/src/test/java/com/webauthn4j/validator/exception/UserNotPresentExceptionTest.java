package com.webauthn4j.validator.exception;

import org.junit.Test;

@SuppressWarnings("ThrowableNotThrown")
public class UserNotPresentExceptionTest {

    private RuntimeException cause = new RuntimeException();

    @Test
    public void test() {
        new UserNotPresentException("dummy");
        new UserNotPresentException("dummy", cause);
    }
}
