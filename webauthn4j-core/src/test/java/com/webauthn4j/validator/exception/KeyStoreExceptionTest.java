package com.webauthn4j.validator.exception;

import org.junit.Test;

@SuppressWarnings("ThrowableNotThrown")
public class KeyStoreExceptionTest {

    private RuntimeException cause = new RuntimeException();

    @Test
    public void test(){
        new KeyStoreException("dummy");
        new KeyStoreException("dummy", cause);
    }
}
