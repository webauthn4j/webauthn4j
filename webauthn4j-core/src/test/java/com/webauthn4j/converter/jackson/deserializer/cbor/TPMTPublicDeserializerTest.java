/*
 * Copyright 2002-2018 the original author or authors.
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

package com.webauthn4j.converter.jackson.deserializer.cbor;


import com.webauthn4j.data.attestation.statement.TPMTPublic;
import com.webauthn4j.util.Base64Util;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Test for TPMTPublicDeserializer
 */
class TPMTPublicDeserializerTest {

    private final TPMTPublicDeserializer deserializer = new TPMTPublicDeserializer();

    @Test
    void shouldDeserializeTPMTPublic() {
        // Given
        String input = "AAEACwAGBHIAIJ3/y/NsODrmmfuYaNxty4nXFTiEvigDkiwSQVi/rSKuABAAEAgAAAAAAAEAxdpvTZNXveIC9cVYzQoxVtJU8uCtmrV5MfmCa3R94axPKdYHCHTc5XkQ4ZhESZ2OQkcDObFw0CK1AauI6cL07TAuRxnHDevohCQD7ZvfwicwphobcPYWxfG3AMrPeEYTfcSy1Gmo4VqrT62GVwhAItKPRNkHUyMSa3AHyYGTn99yTK9PvkdQQEMaTqBkQwvLLPrX0Fvbn2S1sOCVLs+GeSc9bG36gWAfFFAzFqE9B4LDGj5r3e09e8Rrwfqb7w3/g7ferxRrWCxGRIIaPGLtuqa+QivwTkPtr1/TeDCGFT1zYaIDBhpimKsm4TN8ocntBnQaWQVHeYjnIDBOrhidfw";
        byte[] inputBytes = Base64Util.decode(input);

        // When
        TPMTPublic value = deserializer.deserialize(inputBytes);

        // Then
        assertThat(value.getBytes()).isEqualTo(inputBytes);
    }

    @Disabled
    @Test
    void shouldThrowExceptionForInvalidInput() {
        // Given
        byte[] invalidBytes = new byte[]{0x00, 0x01, 0x02}; // Invalid data

        // When
        // Then
        assertThatThrownBy(() -> deserializer.deserialize(invalidBytes))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Disabled
    @Test
    void shouldThrowExceptionForNullInput() {
        // Given
        byte[] input = null;

        // When
        // Then
        assertThatThrownBy(() -> deserializer.deserialize(input))
                .isInstanceOf(IllegalArgumentException.class);
    }
}