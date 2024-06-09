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

import com.webauthn4j.data.extension.SingleValueExtensionOutputBase;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.jetbrains.annotations.NotNull;

public class CredentialPropertiesExtensionClientOutput
        extends SingleValueExtensionOutputBase<CredentialPropertiesOutput>
        implements RegistrationExtensionClientOutput {

    public static final String ID = "credProps";

    public CredentialPropertiesExtensionClientOutput(@NotNull CredentialPropertiesOutput value) {
        super(value);
    }

    @Override
    public @NotNull String getIdentifier() {
        return ID;
    }

    public @NotNull CredentialPropertiesOutput getCredProps() {
        return getValue();
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
