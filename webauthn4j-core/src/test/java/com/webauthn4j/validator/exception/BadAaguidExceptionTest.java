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

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class BadAaguidExceptionTest {

    private final RuntimeException cause = new RuntimeException();

    @Test
    void test() {
        BadAaguidException exception1 = new BadAaguidException("dummy", AAGUID.ZERO, cause);
        BadAaguidException exception2 = new BadAaguidException("dummy", cause);
        BadAaguidException exception3 = new BadAaguidException("dummy");
        BadAaguidException exception4 = new BadAaguidException(cause);
        BadAaguidException exception5 = new BadAaguidException("dummy", AAGUID.ZERO);

        assertAll(
                () -> assertThat(exception1.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception1.getAaguid()).isEqualTo(AAGUID.ZERO),
                () -> assertThat(exception1.getCause()).isEqualTo(cause),

                () -> assertThat(exception2.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception2.getCause()).isEqualTo(cause),

                () -> assertThat(exception3.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception3.getCause()).isNull(),

                () -> assertThat(exception4.getMessage()).isEqualTo(cause.toString()),
                () -> assertThat(exception4.getCause()).isEqualTo(cause),

                () -> assertThat(exception5.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception5.getAaguid()).isEqualTo(AAGUID.ZERO)
        );
    }
}
