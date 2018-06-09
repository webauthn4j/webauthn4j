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

import com.webauthn4j.client.TokenBinding;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.validator.exception.TokenBindingException;

import java.util.Arrays;

public class TokenBindingValidator {

    public void validate(TokenBinding collectedClientDataTokenBinding, byte[] serverTokenBindingId) {
        if (collectedClientDataTokenBinding == null) {
            // nop
        } else {
            byte[] clientDataTokenBindingId;
            if (collectedClientDataTokenBinding.getId() == null) {
                clientDataTokenBindingId = null;
            } else {
                clientDataTokenBindingId = Base64UrlUtil.decode(collectedClientDataTokenBinding.getId());
            }
            switch (collectedClientDataTokenBinding.getStatus()) {
                case NOT_SUPPORTED:
                    break;
                case SUPPORTED:
                    break;
                case PRESENT:
                    if (!Arrays.equals(clientDataTokenBindingId, serverTokenBindingId)) {
                        throw new TokenBindingException("TokenBinding id does not match");
                    }
            }
        }
    }
}