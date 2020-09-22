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

import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.FIDOAppIDExtensionClientOutput;
import com.webauthn4j.validator.exception.UnexpectedExtensionException;
import org.junit.jupiter.api.Test;
import test.TestExtensionAuthenticatorOutput;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuthenticatorExtensionValidatorTest {

    private final AuthenticatorExtensionValidator extensionValidator = new AuthenticatorExtensionValidator();

    @Test
    void expected_extension_does_not_exist_test() {
        AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration builder = new AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration();
        builder.set("test", true);
        List<String> expectedExtensions = Arrays.asList(FIDOAppIDExtensionClientOutput.ID, TestExtensionAuthenticatorOutput.ID);
        extensionValidator.validate(builder.build(), expectedExtensions);
    }

    @Test
    void expected_extension_does_exist_test() {
        AuthenticationExtensionsAuthenticatorOutputs.BuilderForAuthentication builder = new AuthenticationExtensionsAuthenticatorOutputs.BuilderForAuthentication();
        builder.set("expected", true);
        List<String> expectedExtensions = Collections.singletonList("expected");
        AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput> outputs = builder.build();
        extensionValidator.validate(outputs, expectedExtensions);
    }

    @Test
    void unexpected_extension_does_exist_test() {
        AuthenticationExtensionsAuthenticatorOutputs.BuilderForAuthentication builder = new AuthenticationExtensionsAuthenticatorOutputs.BuilderForAuthentication();
        builder.set("unknown", true);
        List<String> expectedExtensions = Collections.emptyList();
        AuthenticationExtensionsAuthenticatorOutputs<AuthenticationExtensionAuthenticatorOutput> outputs = builder.build();
        assertThrows(UnexpectedExtensionException.class,
                () -> extensionValidator.validate(outputs, expectedExtensions)
        );
    }

    @Test
    void unexpected_authenticator_extension_does_exist_test() {
        AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration builder = new AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration();
        builder.set("test", true);
        List<String> expectedExtensionIdentifiers = Collections.emptyList();
        AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> outputs = builder.build();
        assertThrows(UnexpectedExtensionException.class,
                () -> extensionValidator.validate(outputs, expectedExtensionIdentifiers)
        );
    }

    @Test
    void expectedExtensions_null_test() {
        AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration builder = new AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration();
        builder.set("test", true);
        AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> outputs = builder.build();
        assertThatCode(()-> extensionValidator.validate(outputs, null)).doesNotThrowAnyException();
    }

    @Test
    void authenticatorOutputs_null_test() {
        extensionValidator.validate(null, null);
    }

}