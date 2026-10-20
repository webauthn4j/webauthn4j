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

package com.webauthn4j.appattest.data.extension;

import com.webauthn4j.data.extension.SingleValueExtensionInputBase;
import com.webauthn4j.appattest.data.ValidationCategory;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.jetbrains.annotations.NotNull;

public class AppleValidationCategory01ExtensionAuthenticatorOutput extends SingleValueExtensionInputBase<ValidationCategory>
        implements RegistrationExtensionAuthenticatorOutput, AuthenticationExtensionAuthenticatorOutput {

    public static final String ID = "apple_validation_category_01";

    public AppleValidationCategory01ExtensionAuthenticatorOutput(@NotNull ValidationCategory value) {
        super(value);
    }

    @Override
    public @NotNull String getIdentifier() {
        return ID;
    }

    public @NotNull ValidationCategory getValidationCategory() {
        return getValue();
    }

    @SuppressWarnings({"ConstantConditions", "java:S2583"})
    @Override
    public void validate() {
        if (getValue() == null) {
            throw new ConstraintViolationException("value must not be null");
        }
    }
}
