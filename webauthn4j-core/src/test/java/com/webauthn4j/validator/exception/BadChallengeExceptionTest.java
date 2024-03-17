/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.validator.exception;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class BadChallengeExceptionTest {

    private final RuntimeException cause = new RuntimeException();
    private final byte[] expected = new byte[32];
    private final byte[] actual = new byte[32];

    @Test
    void test() {
        BadChallengeException exception1 = new BadChallengeException("dummy", expected, actual, cause);
        BadChallengeException exception2 = new BadChallengeException("dummy", expected, actual);
        BadChallengeException exception3 = new BadChallengeException("dummy", cause);
        BadChallengeException exception4 = new BadChallengeException("dummy");
        BadChallengeException exception5 = new BadChallengeException(cause);

        assertAll(
                () -> assertThat(exception1.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception1.getExpected()).isEqualTo(expected),
                () -> assertThat(exception1.getActual()).isEqualTo(actual),
                () -> assertThat(exception1.getCause()).isEqualTo(cause),

                () -> assertThat(exception2.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception2.getExpected()).isEqualTo(expected),
                () -> assertThat(exception2.getActual()).isEqualTo(actual),
                () -> assertThat(exception2.getCause()).isNull(),

                () -> assertThat(exception3.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception3.getCause()).isEqualTo(cause),

                () -> assertThat(exception4.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception4.getCause()).isNull(),

                () -> assertThat(exception5.getMessage()).isEqualTo(cause.toString()),
                () -> assertThat(exception5.getCause()).isEqualTo(cause)
        );
    }
}
