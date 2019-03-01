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

package com.webauthn4j.validator;

import com.webauthn4j.response.client.TokenBinding;
import com.webauthn4j.response.client.TokenBindingStatus;
import com.webauthn4j.validator.exception.TokenBindingException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

public class TokenBindingValidatorTest {

    private TokenBindingValidator target = new TokenBindingValidator();

    @Test
    public void validate_test() {
        byte[] bindingId = new byte[]{0x01, 0x23, 0x45};
        TokenBinding tokenBinding = new TokenBinding(TokenBindingStatus.PRESENT, bindingId);
        target.validate(tokenBinding, bindingId);
    }

    @Test
    public void validate_invalid_bindingId_test() {
        byte[] bindingId = new byte[]{0x01, 0x23, 0x45};
        byte[] invalidBindingId = new byte[]{0x00, 0x00, 0x00};
        TokenBinding tokenBinding = new TokenBinding(TokenBindingStatus.PRESENT, bindingId);
        assertThrows(TokenBindingException.class,
                () -> target.validate(tokenBinding, invalidBindingId)
        );
    }

    @Test
    public void validate_TokenBinding_not_supported_test() {
        byte[] bindingId = null;
        TokenBinding tokenBinding = new TokenBinding(TokenBindingStatus.NOT_SUPPORTED, bindingId);
        target.validate(tokenBinding, bindingId);
    }

    @Test
    public void validate_TokenBinding_supported_test() {
        byte[] bindingId = null;
        TokenBinding tokenBinding = new TokenBinding(TokenBindingStatus.SUPPORTED, bindingId);
        target.validate(tokenBinding, bindingId);
    }
}
