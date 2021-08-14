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

public class UserVerificationMethodExtensionClientInput extends SingleValueExtensionInputBase<Boolean> implements RegistrationExtensionClientInput, AuthenticationExtensionClientInput {

    public static final String ID = "uvm";

    public UserVerificationMethodExtensionClientInput(@NonNull Boolean appId) {
        super(appId);
    }

    @Override
    public @NonNull String getIdentifier() {
        return ID;
    }

    public @NonNull Boolean getUvm() {
        return getValue(ID);
    }

    @SuppressWarnings({"ConstantConditions", "java:S2583"})
    @Override
    public void validate() {
        // value can be null when deserialized by Jackson
        if (getValue() == null) {
            throw new ConstraintViolationException("value must not be null");
        }
    }

}
