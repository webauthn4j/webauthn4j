package com.webauthn4j.validator.exception;

import org.junit.Test;

@SuppressWarnings("ThrowableNotThrown")
public class MissingChallengeExceptionTest {

    private RuntimeException cause = new RuntimeException();

    @Test
    public void test(){
        new MissingChallengeException("dummy");
        new MissingChallengeException("dummy", cause);
    }
}
