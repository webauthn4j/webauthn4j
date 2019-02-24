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

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

@SuppressWarnings("ThrowableNotThrown")
public class MissingChallengeExceptionTest {

    private RuntimeException cause = new RuntimeException();

    @Test
    public void test() {
        MissingChallengeException exception;

        exception = new MissingChallengeException("dummy", cause);
        assertThat(exception.getMessage()).isEqualTo("dummy");
        assertThat(exception.getCause()).isEqualTo(cause);

        exception = new MissingChallengeException("dummy");
        assertThat(exception.getMessage()).isEqualTo("dummy");
        assertThat(exception.getCause()).isNull();

        exception = new MissingChallengeException(cause);
        assertThat(exception.getMessage()).isEqualTo(cause.toString());
        assertThat(exception.getCause()).isEqualTo(cause);
    }
}
