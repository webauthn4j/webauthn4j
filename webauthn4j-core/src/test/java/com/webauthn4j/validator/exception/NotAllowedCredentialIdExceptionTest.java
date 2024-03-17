/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.validator.exception;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class NotAllowedCredentialIdExceptionTest {

    private final RuntimeException cause = new RuntimeException();
    private final List<byte[]> expected = new ArrayList<>();
    private final byte[] actual = new byte[32];

    @Test
    void test() {
        NotAllowedCredentialIdException exception1 = new NotAllowedCredentialIdException("dummy", expected, actual, cause);
        NotAllowedCredentialIdException exception2 = new NotAllowedCredentialIdException("dummy", expected, actual);
        NotAllowedCredentialIdException exception3 = new NotAllowedCredentialIdException("dummy", cause);
        NotAllowedCredentialIdException exception4 = new NotAllowedCredentialIdException("dummy");
        NotAllowedCredentialIdException exception5 = new NotAllowedCredentialIdException(cause);

        assertAll(
                () -> assertThat(exception1.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception1.getCause()).isEqualTo(cause),

                () -> assertThat(exception2.getMessage()).isEqualTo("dummy"),
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