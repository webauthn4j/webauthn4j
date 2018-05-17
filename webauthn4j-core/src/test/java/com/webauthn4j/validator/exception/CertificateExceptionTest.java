package com.webauthn4j.validator.exception;

import org.junit.Test;

@SuppressWarnings("ThrowableNotThrown")
public class CertificateExceptionTest {

    private RuntimeException cause = new RuntimeException();

    @Test
    public void test() {
        new CertificateException("dummy");
        new CertificateException("dummy", cause);
    }
}