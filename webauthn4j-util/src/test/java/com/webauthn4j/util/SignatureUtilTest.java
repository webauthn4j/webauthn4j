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

package com.webauthn4j.util;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class SignatureUtilTest {

    @Test
    public void createSignature_test() {
        SignatureUtil.createSignature("SHA256withRSA");
    }

    @Test
    public void createSignature_test_with_null() {
        assertThatThrownBy(() -> SignatureUtil.createSignature(null))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("algorithm is required; it must not be null");
    }

    @Test
    public void createSignature_test_with_illegal_argument() {
        assertThatThrownBy(() -> SignatureUtil.createSignature("dummyAlg"))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("dummyAlg Signature not available");
    }
}
