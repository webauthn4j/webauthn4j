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

package com.webauthn4j.converter.jackson.deserializer;


import com.webauthn4j.data.attestation.statement.TPMTPublic;
import com.webauthn4j.util.Base64Util;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

class TPMTPublicDeserializerTest {

    private TPMTPublicDeserializer deserializer = new TPMTPublicDeserializer();

    @Test
    void deserialize_test() throws IOException {
        String input = "AAEACwAGBHIAIJ3/y/NsODrmmfuYaNxty4nXFTiEvigDkiwSQVi/rSKuABAAEAgAAAAAAAEAxdpvTZNXveIC9cVYzQoxVtJU8uCtmrV5MfmCa3R94axPKdYHCHTc5XkQ4ZhESZ2OQkcDObFw0CK1AauI6cL07TAuRxnHDevohCQD7ZvfwicwphobcPYWxfG3AMrPeEYTfcSy1Gmo4VqrT62GVwhAItKPRNkHUyMSa3AHyYGTn99yTK9PvkdQQEMaTqBkQwvLLPrX0Fvbn2S1sOCVLs+GeSc9bG36gWAfFFAzFqE9B4LDGj5r3e09e8Rrwfqb7w3/g7ferxRrWCxGRIIaPGLtuqa+QivwTkPtr1/TeDCGFT1zYaIDBhpimKsm4TN8ocntBnQaWQVHeYjnIDBOrhidfw";
        byte[] inputBytes = Base64Util.decode(input);
        TPMTPublic value = deserializer.deserialize(inputBytes);
        assertThat(value.getBytes()).isEqualTo(inputBytes);
    }
}