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

import com.webauthn4j.data.extension.HMACGetSecretOutput;
import com.webauthn4j.data.extension.SingleValueExtensionOutputBase;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.jetbrains.annotations.NotNull;

public class HMACSecretAuthenticationExtensionClientOutput extends SingleValueExtensionOutputBase<HMACGetSecretOutput> implements AuthenticationExtensionClientOutput {

    public static final String ID = "hmac-secret";
    public static final String KEY_HMAC_GET_SECRET = "hmacGetSecret";

    public HMACSecretAuthenticationExtensionClientOutput(@NotNull HMACGetSecretOutput value) {
        super(value);
    }

    @Override
    public @NotNull String getIdentifier() {
        return ID;
    }

    @Override
    public @NotNull HMACGetSecretOutput getValue(@NotNull String key) {
        if (!key.equals(KEY_HMAC_GET_SECRET)) {
            throw new IllegalArgumentException(String.format("%s is the only valid key.", KEY_HMAC_GET_SECRET));
        }
        return getValue();
    }

    @SuppressWarnings({"ConstantConditions", "java:S2583"})
    @Override
    public void validate() {
        // value can be null when deserialized by Jackson
        if (getValue() == null) {
            throw new ConstraintViolationException("value must not be null");
        }
        if (getValue().getOutput1() == null) {
            throw new ConstraintViolationException("output1 must not be null");
        }
        if (getValue().getOutput1().length != 32) {
            throw new ConstraintViolationException("output1 must be 32 bytes length");
        }
        if (getValue().getOutput2() != null && getValue().getOutput2().length != 32) {
            throw new ConstraintViolationException("output2 must be 32 bytes length");
        }
    }
}
