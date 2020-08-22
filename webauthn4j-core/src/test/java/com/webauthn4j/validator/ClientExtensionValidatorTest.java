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

class ClientExtensionValidatorTest {

    private final ClientExtensionValidator extensionValidator = new ClientExtensionValidator();

    @Test
    void expected_extension_does_not_exist_test() {
        AuthenticationExtensionsClientOutputs.BuilderForRegistration builder = new AuthenticationExtensionsClientOutputs.BuilderForRegistration();
        builder.set("test", true);
        List<String> expectedExtensions = Arrays.asList(FIDOAppIDExtensionClientOutput.ID, TestExtensionAuthenticatorOutput.ID);
        extensionValidator.validate(builder.build(), expectedExtensions);
    }

    @Test
    void expected_extension_does_exist_test() {
        AuthenticationExtensionsClientOutputs.BuilderForAuthentication builder = new AuthenticationExtensionsClientOutputs.BuilderForAuthentication();
        builder.setAppid(true);
        List<String> expectedExtensions = Collections.singletonList(FIDOAppIDExtensionClientOutput.ID);
        extensionValidator.validate(builder.build(), expectedExtensions);
    }

    @Test
    void unexpected_extension_does_exist_test() {
        AuthenticationExtensionsClientOutputs.BuilderForAuthentication builder = new AuthenticationExtensionsClientOutputs.BuilderForAuthentication();
        builder.set("unknown", true);
        List<String> expectedExtensions = Collections.emptyList();
        AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> outputs = builder.build();
        assertThrows(UnexpectedExtensionException.class,
                () -> extensionValidator.validate(outputs, expectedExtensions)
        );
    }

    @Test
    void expectedExtensions_null_test() {
        AuthenticationExtensionsClientOutputs.BuilderForRegistration builder = new AuthenticationExtensionsClientOutputs.BuilderForRegistration();
        builder.set("test", true);
        AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> outputs = builder.build();
        assertThatCode(()-> extensionValidator.validate(outputs, null)).doesNotThrowAnyException();
    }

    @Test
    void clientOutputs_null_test() {
        extensionValidator.validate(null, null);
    }

}