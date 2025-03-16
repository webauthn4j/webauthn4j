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

package com.webauthn4j.util;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("ConstantConditions")
class SignatureUtilTest {

    @Test
    void createRS256_test() {
        assertThat(SignatureUtil.createRS256().getAlgorithm()).isEqualTo("SHA256withRSA");
    }

    @Test
    void createES256_test() {
        assertThat(SignatureUtil.createES256().getAlgorithm()).isEqualTo("SHA256withECDSA");
    }

    @Nested
    class createSignatureTest{
        @Deprecated
        @Test
        void createSignature_test() {
            SignatureUtil.createSignature("SHA256withRSA");
        }

        @Deprecated
        @Test
        void createSignature_test_with_null() {
            Throwable t = assertThrows(IllegalArgumentException.class,
                    () -> SignatureUtil.createSignature((String) null)
            );
            assertThat(t).hasMessage("algorithm is required; it must not be null");
        }

        @Deprecated
        @Test
        void createSignature_test_with_illegal_argument() {
            Throwable t = assertThrows(IllegalArgumentException.class,
                    () -> SignatureUtil.createSignature("dummyAlg")
            );
            assertThat(t).hasMessageContaining("dummyAlg Signature not available");
        }

    }
}
