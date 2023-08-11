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

import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;

class BadAlgorithmExceptionTest {

    private final RuntimeException cause = new RuntimeException();

    @Test
    void test() {
        BadAlgorithmException exception1 = new BadAlgorithmException("dummy", COSEAlgorithmIdentifier.ES256, COSEAlgorithmIdentifier.ES384, cause);
        BadAlgorithmException exception2 = new BadAlgorithmException("dummy", COSEAlgorithmIdentifier.ES256, COSEAlgorithmIdentifier.ES384);
        BadAlgorithmException exception3 = new BadAlgorithmException("dummy", cause);
        BadAlgorithmException exception4 = new BadAlgorithmException("dummy");
        BadAlgorithmException exception5 = new BadAlgorithmException(cause);

        assertAll(
                () -> assertThat(exception1.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception1.getActual()).isEqualTo(COSEAlgorithmIdentifier.ES256),
                () -> assertThat(exception1.getExpected()).isEqualTo(COSEAlgorithmIdentifier.ES384),
                () -> assertThat(exception1.getCause()).isEqualTo(cause),

                () -> assertThat(exception2.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception2.getActual()).isEqualTo(COSEAlgorithmIdentifier.ES256),
                () -> assertThat(exception2.getExpected()).isEqualTo(COSEAlgorithmIdentifier.ES384),

                () -> assertThat(exception3.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception3.getCause()).isEqualTo(cause),

                () -> assertThat(exception4.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception4.getCause()).isNull(),

                () -> assertThat(exception5.getMessage()).isEqualTo(cause.toString()),
                () -> assertThat(exception5.getCause()).isEqualTo(cause)
        );
    }
}
