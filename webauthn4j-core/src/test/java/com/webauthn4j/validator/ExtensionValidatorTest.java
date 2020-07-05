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

import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.ExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.FIDOAppIDExtensionClientOutput;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.validator.exception.UnexpectedExtensionException;
import org.junit.jupiter.api.Test;
import test.TestExtensionAuthenticatorOutput;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ExtensionValidatorTest {

    private final ExtensionValidator extensionValidator = new ExtensionValidator();

    @Test
    void expected_extension_does_not_exist_test() {
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientOutputs = new AuthenticationExtensionsClientOutputs<>();
        AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration builder = new AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration();
        builder.set("test", true);
        AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorOutputs = builder.build();
        List<String> expectedExtensions = Arrays.asList(FIDOAppIDExtensionClientOutput.ID, TestExtensionAuthenticatorOutput.ID);
        extensionValidator.validate(clientOutputs, authenticatorOutputs, expectedExtensions);
    }

    @Test
    void expected_extension_does_exist_test() {
        AuthenticationExtensionsClientOutputs.BuilderForAuthentication builder = new AuthenticationExtensionsClientOutputs.BuilderForAuthentication();
        builder.setAppid(true);
        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientOutputs = builder.build();
        AuthenticationExtensionsAuthenticatorOutputs<ExtensionAuthenticatorOutput> authenticatorOutputs = new AuthenticationExtensionsAuthenticatorOutputs<>();
        List<String> expectedExtensions = Collections.singletonList(FIDOAppIDExtensionClientOutput.ID);
        extensionValidator.validate(clientOutputs, authenticatorOutputs, expectedExtensions);
    }

    @Test
    void unexpected_extension_does_exist_test() {
        AuthenticationExtensionsClientOutputs.BuilderForAuthentication builder = new AuthenticationExtensionsClientOutputs.BuilderForAuthentication();
        builder.set("unknown", true);
        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientOutputs = builder.build();
        AuthenticationExtensionsAuthenticatorOutputs<ExtensionAuthenticatorOutput> authenticatorOutputs = new AuthenticationExtensionsAuthenticatorOutputs<>();
        List<String> expectedExtensions = Collections.emptyList();
        assertThrows(UnexpectedExtensionException.class,
                () -> extensionValidator.validate(clientOutputs, authenticatorOutputs, expectedExtensions)
        );
    }

    @Test
    void unexpected_authenticator_extension_does_exist_test() {
        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientOutputs = new AuthenticationExtensionsClientOutputs<>();
        AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration builder = new AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration();
        builder.set("test", true);
        AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorOutputs = builder.build();
        List<String> expectedExtensionIdentifiers = Collections.emptyList();
        assertThrows(UnexpectedExtensionException.class,
                () -> extensionValidator.validate(clientOutputs, authenticatorOutputs, expectedExtensionIdentifiers)
        );
    }

    @Test
    void expectedExtensions_null_test() {
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientOutputs = new AuthenticationExtensionsClientOutputs<>();
        AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration builder = new AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration();
        builder.set("test", true);
        AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorOutputs = builder.build();
        assertThatCode(()-> extensionValidator.validate(clientOutputs, authenticatorOutputs, null)).doesNotThrowAnyException();

    }

    @Test
    void clientOutputs_and_authenticatorOutputs_null_test() {
        extensionValidator.validate(null, null, null);
    }

}