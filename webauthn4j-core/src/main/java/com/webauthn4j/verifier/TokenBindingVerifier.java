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

package com.webauthn4j.verifier;

import com.webauthn4j.data.client.TokenBinding;
import com.webauthn4j.data.client.TokenBindingStatus;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.verifier.exception.TokenBindingException;
import org.jetbrains.annotations.Nullable;

import java.security.MessageDigest;

/**
 * Verifies the specified {@link TokenBinding}
 */
class TokenBindingVerifier {

    // ~ Methods
    // ========================================================================================================

    public void verify(@Nullable TokenBinding clientDataTokenBinding, @Nullable byte[] serverTokenBindingId) {
        if (clientDataTokenBinding != null) {
            byte[] clientDataTokenBindingId;
            if (clientDataTokenBinding.getId() == null) {
                clientDataTokenBindingId = null;
            }
            else {
                clientDataTokenBindingId = Base64UrlUtil.decode(clientDataTokenBinding.getId());
            }
            TokenBindingStatus tokenBindingStatus = clientDataTokenBinding.getStatus();
            if (TokenBindingStatus.NOT_SUPPORTED.equals(tokenBindingStatus) || TokenBindingStatus.SUPPORTED.equals(tokenBindingStatus)) {
                //nop
            }
            else if (TokenBindingStatus.PRESENT.equals(tokenBindingStatus)) {
                if(!MessageDigest.isEqual(clientDataTokenBindingId, serverTokenBindingId)){
                    throw new TokenBindingException("TokenBinding id does not match");
                }
            }
            else { //token binding status is unknown value
                throw new TokenBindingException("Unknown TokenBindingStatus value");
            }
        }
    }
}