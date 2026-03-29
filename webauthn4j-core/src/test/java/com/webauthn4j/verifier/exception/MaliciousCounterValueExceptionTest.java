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

package com.webauthn4j.verifier.exception;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class MaliciousCounterValueExceptionTest {

    private final RuntimeException cause = new RuntimeException();
    private final long storedCounter = 100L;
    private final long presentedCounter = 50L;

    @Test
    void test() {
        MaliciousCounterValueException exception1 =
                new MaliciousCounterValueException("dummy", storedCounter, presentedCounter, cause);
        MaliciousCounterValueException exception2 =
                new MaliciousCounterValueException("dummy", storedCounter, presentedCounter);
        MaliciousCounterValueException exception3 =
                new MaliciousCounterValueException("dummy", cause);  // deprecated
        MaliciousCounterValueException exception4 =
                new MaliciousCounterValueException("dummy");  // deprecated
        MaliciousCounterValueException exception5 =
                new MaliciousCounterValueException(cause);  // deprecated

        assertAll(
                () -> assertThat(exception1.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception1.getStoredCounter()).isEqualTo(100L),
                () -> assertThat(exception1.getPresentedCounter()).isEqualTo(50L),
                () -> assertThat(exception1.getCause()).isEqualTo(cause),

                () -> assertThat(exception2.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception2.getStoredCounter()).isEqualTo(100L),
                () -> assertThat(exception2.getPresentedCounter()).isEqualTo(50L),
                () -> assertThat(exception2.getCause()).isNull(),

                () -> assertThat(exception3.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception3.getStoredCounter()).isEqualTo(0L),  // default
                () -> assertThat(exception3.getPresentedCounter()).isEqualTo(0L),  // default
                () -> assertThat(exception3.getCause()).isEqualTo(cause),

                () -> assertThat(exception4.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception4.getStoredCounter()).isEqualTo(0L),
                () -> assertThat(exception4.getPresentedCounter()).isEqualTo(0L),
                () -> assertThat(exception4.getCause()).isNull(),

                () -> assertThat(exception5.getMessage()).isEqualTo(cause.toString()),
                () -> assertThat(exception5.getStoredCounter()).isEqualTo(0L),
                () -> assertThat(exception5.getPresentedCounter()).isEqualTo(0L),
                () -> assertThat(exception5.getCause()).isEqualTo(cause)
        );
    }
}
