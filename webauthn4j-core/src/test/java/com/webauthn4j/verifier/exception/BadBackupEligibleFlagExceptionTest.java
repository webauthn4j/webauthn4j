package com.webauthn4j.verifier.exception;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class BadBackupEligibleFlagExceptionTest {

    private final RuntimeException cause = new RuntimeException();

    @Test
    void test() {
        BadBackupEligibleFlagException exception1 = new BadBackupEligibleFlagException("dummy", cause);
        BadBackupEligibleFlagException exception2 = new BadBackupEligibleFlagException("dummy");
        BadBackupEligibleFlagException exception3 = new BadBackupEligibleFlagException(cause);

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