package com.webauthn4j.validator.exception;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class IllegalBackupStateExceptionTest {

    private final RuntimeException cause = new RuntimeException();

    @Test
    void test() {
        IllegalBackupStateException exception1 = new IllegalBackupStateException("dummy", cause);
        IllegalBackupStateException exception2 = new IllegalBackupStateException("dummy");
        IllegalBackupStateException exception3 = new IllegalBackupStateException(cause);

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