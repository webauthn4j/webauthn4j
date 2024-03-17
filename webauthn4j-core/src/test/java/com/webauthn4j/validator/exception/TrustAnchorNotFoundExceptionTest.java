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

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;


class TrustAnchorNotFoundExceptionTest {

    private final RuntimeException cause = new RuntimeException();
    private final AAGUID aaguid = new AAGUID(UUID.randomUUID());
    private final byte[] subjectKeyIdentifier = new byte[32];

    @Test
    void test() {
        TrustAnchorNotFoundException exception1 = new TrustAnchorNotFoundException("dummy", aaguid);
        TrustAnchorNotFoundException exception2 = new TrustAnchorNotFoundException("dummy", subjectKeyIdentifier);
        TrustAnchorNotFoundException exception3 = new TrustAnchorNotFoundException("dummy", cause);
        TrustAnchorNotFoundException exception4 = new TrustAnchorNotFoundException("dummy");
        TrustAnchorNotFoundException exception5 = new TrustAnchorNotFoundException(cause);

        assertAll(
                () -> assertThat(exception1.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception1.getAaguid()).isEqualTo(aaguid),
                () -> assertThat(exception1.getSubjectKeyIdentifier()).isNull(),
                () -> assertThat(exception1.getCause()).isNull(),

                () -> assertThat(exception2.getMessage()).isEqualTo("dummy"),
                () -> assertThat(exception2.getAaguid()).isNull(),
                () -> assertThat(exception2.getSubjectKeyIdentifier()).isEqualTo(subjectKeyIdentifier),
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