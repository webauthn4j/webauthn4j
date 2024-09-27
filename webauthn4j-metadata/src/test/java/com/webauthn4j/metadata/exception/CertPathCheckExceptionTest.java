package com.webauthn4j.metadata.exception;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class CertPathCheckExceptionTest {

    private final RuntimeException cause = new RuntimeException();

    @Test
    void test() {
        CertPathCheckException exception1 = new CertPathCheckException("dummy", cause);
        CertPathCheckException exception2 = new CertPathCheckException("dummy");
        CertPathCheckException exception3 = new CertPathCheckException(cause);

        assertAll(
                () -> assertThat(exception1.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception1.getCause()).isEqualTo(cause),

                () -> assertThat(exception2.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception2.getCause()).isNull(),

                () -> assertThat(exception3.getMessage()).isEqualTo(cause.toString()),
                () -> assertThat(exception3.getCause()).isEqualTo(cause)
        );
    }

}