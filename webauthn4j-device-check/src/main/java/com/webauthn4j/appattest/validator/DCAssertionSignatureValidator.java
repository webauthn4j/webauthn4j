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

package com.webauthn4j.appattest.validator;

import com.webauthn4j.data.CoreAuthenticationData;
import com.webauthn4j.util.MessageDigestUtil;
import com.webauthn4j.validator.AssertionSignatureValidator;
import org.jetbrains.annotations.NotNull;

import java.nio.ByteBuffer;

public class DCAssertionSignatureValidator extends AssertionSignatureValidator {

    // ~ Methods
    // ========================================================================================================

    @Override
    protected @NotNull byte[] getSignedData(@NotNull CoreAuthenticationData authenticationData) {
        byte[] rawAuthenticatorData = authenticationData.getAuthenticatorDataBytes();
        byte[] clientDataHash = authenticationData.getClientDataHash();
        byte[] concatenated = ByteBuffer.allocate(rawAuthenticatorData.length + clientDataHash.length).put(rawAuthenticatorData).put(clientDataHash).array();
        return MessageDigestUtil.createSHA256().digest(concatenated);
    }
}
