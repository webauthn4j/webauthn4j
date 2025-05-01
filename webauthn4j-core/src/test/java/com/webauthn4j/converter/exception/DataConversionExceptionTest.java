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

package com.webauthn4j.converter.exception;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

class DataConversionExceptionTest {

    @Test
    void shouldCreateExceptionWithCause() {
        RuntimeException cause = new RuntimeException();
        DataConversionException exception = new DataConversionException(cause);
        Assertions.assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    void shouldCreateExceptionWithMessage() {
        String message = "test message";
        DataConversionException exception = new DataConversionException(message);
        Assertions.assertThat(exception.getMessage()).isEqualTo(message);
    }

    @Test
    void shouldCreateExceptionWithMessageAndCause() {
        String message = "test message";
        RuntimeException cause = new RuntimeException();
        DataConversionException exception = new DataConversionException(message, cause);
        Assertions.assertThat(exception.getMessage()).isEqualTo(message);
        Assertions.assertThat(exception.getCause()).isEqualTo(cause);
    }
}
