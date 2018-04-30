package com.webauthn4j.validator.exception;

import org.junit.Test;

@SuppressWarnings("ThrowableNotThrown")
public class BadChallengeExceptionTest {

    private RuntimeException cause = new RuntimeException();

    @Test
    public void test(){
        new BadChallengeException("dummy");
        new BadChallengeException("dummy", cause);
    }
}
