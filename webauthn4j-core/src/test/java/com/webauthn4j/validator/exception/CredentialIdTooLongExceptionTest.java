package com.webauthn4j.validator.exception;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class CredentialIdTooLongExceptionTest {

    private final RuntimeException cause = new RuntimeException();

    @Test
    void test() {
        CredentialIdTooLongException exception1 = new CredentialIdTooLongException("dummy", cause);
        CredentialIdTooLongException exception2 = new CredentialIdTooLongException("dummy");
        CredentialIdTooLongException exception3 = new CredentialIdTooLongException(cause);

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