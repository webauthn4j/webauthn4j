package com.webauthn4j.validator.exception;

import org.junit.Test;

@SuppressWarnings("ThrowableNotThrown")
public class UserNotVerifiedExceptionTest {

    private RuntimeException cause = new RuntimeException();

    @Test
    public void test(){
        new UserNotVerifiedException("dummy");
        new UserNotVerifiedException("dummy", cause);
    }
}
