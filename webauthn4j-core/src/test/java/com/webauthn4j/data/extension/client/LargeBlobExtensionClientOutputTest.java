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

package com.webauthn4j.data.extension.client;

import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

class LargeBlobExtensionClientOutputTest {

    @Test
    void validate_with_valid_value() {
        assertThatCode(new LargeBlobExtensionClientOutput(new AuthenticationExtensionsLargeBlobOutputs(true, null, null))::validate).doesNotThrowAnyException();
    }

    @Test
    void validate_with_null_value() {
        assertThatThrownBy(new LargeBlobExtensionClientOutput(null)::validate).isInstanceOf(ConstraintViolationException.class);
    }

    @Test
    void getIdentifier_returns_largeBlob() {
        LargeBlobExtensionClientOutput target = new LargeBlobExtensionClientOutput(new AuthenticationExtensionsLargeBlobOutputs(true, null, null));
        assertThat(target.getIdentifier()).isEqualTo("largeBlob");
    }

    @Test
    void getValue_with_valid_key() {
        AuthenticationExtensionsLargeBlobOutputs outputs = new AuthenticationExtensionsLargeBlobOutputs(true, null, null);
        LargeBlobExtensionClientOutput target = new LargeBlobExtensionClientOutput(outputs);
        assertThat(target.getValue("largeBlob")).isSameAs(outputs);
    }

    @Test
    void getValue_with_invalid_key() {
        LargeBlobExtensionClientOutput target = new LargeBlobExtensionClientOutput(new AuthenticationExtensionsLargeBlobOutputs(true, null, null));
        assertThatThrownBy(() -> target.getValue("invalid")).isInstanceOf(IllegalArgumentException.class);
    }

}
