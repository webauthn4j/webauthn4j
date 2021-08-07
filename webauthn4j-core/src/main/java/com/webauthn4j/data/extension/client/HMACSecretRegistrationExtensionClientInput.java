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

import com.webauthn4j.data.extension.SingleValueExtensionInputBase;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

public class HMACSecretRegistrationExtensionClientInput extends SingleValueExtensionInputBase<Boolean>
        implements RegistrationExtensionClientInput {

    public static final String ID = "hmac-secret";
    public static final String KEY_HMAC_CREATE_SECRET = "hmacCreateSecret";

    public HMACSecretRegistrationExtensionClientInput(@Nullable Boolean value) {
        super(value);
    }

    @Override
    public @NonNull String getIdentifier() {
        return ID;
    }

    public @Nullable Boolean getValue(@NonNull String key) {
        if (!key.equals(KEY_HMAC_CREATE_SECRET)) {
            throw new IllegalArgumentException(String.format("%s is the only valid key.", KEY_HMAC_CREATE_SECRET));
        }
        return getValue();
    }

    @Override
    public void validate() {
        if (getValue() == null) {
            throw new ConstraintViolationException("value must not be null");
        }
    }
}
