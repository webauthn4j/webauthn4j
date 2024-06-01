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

package com.webauthn4j.validator;

import com.webauthn4j.data.client.TokenBinding;
import com.webauthn4j.data.client.TokenBindingStatus;
import com.webauthn4j.validator.exception.TokenBindingException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("ConstantConditions")
class TokenBindingVerifierTest {

    private final TokenBindingVerifier target = new TokenBindingVerifier();

    @Test
    void verify_test() {
        byte[] bindingId = new byte[]{0x01, 0x23, 0x45};
        TokenBinding tokenBinding = new TokenBinding(TokenBindingStatus.PRESENT, bindingId);
        target.verify(tokenBinding, bindingId);
    }

    @Test
    void verify_invalid_bindingId_test() {
        byte[] bindingId = new byte[]{0x01, 0x23, 0x45};
        byte[] invalidBindingId = new byte[]{0x00, 0x00, 0x00};
        TokenBinding tokenBinding = new TokenBinding(TokenBindingStatus.PRESENT, bindingId);
        assertThrows(TokenBindingException.class,
                () -> target.verify(tokenBinding, invalidBindingId)
        );
    }

    @Test
    void verify_TokenBindingStatus_not_supported_test() {
        byte[] bindingId = null;
        TokenBinding tokenBinding = new TokenBinding(TokenBindingStatus.NOT_SUPPORTED, bindingId);
        target.verify(tokenBinding, bindingId);
    }

    @Test
    void verify_TokenBindingStatus_supported_test() {
        byte[] bindingId = null;
        TokenBinding tokenBinding = new TokenBinding(TokenBindingStatus.SUPPORTED, bindingId);
        target.verify(tokenBinding, bindingId);
    }

    @Test
    void verify_TokenBindingStatus_unknown_value_test() {
        byte[] bindingId = null;
        TokenBinding tokenBinding = new TokenBinding(TokenBindingStatus.create("unknown"), bindingId);
        assertThrows(TokenBindingException.class,
                () -> target.verify(tokenBinding, bindingId)
        );
    }

}
