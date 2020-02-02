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
import com.webauthn4j.data.extension.authenticator.SupportedExtensionsExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.ExtensionClientOutput;
import com.webauthn4j.data.extension.client.FIDOAppIDExtensionClientOutput;
import com.webauthn4j.data.extension.client.SupportedExtensionsExtensionClientOutput;
import com.webauthn4j.validator.exception.UnexpectedExtensionException;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.assertThrows;

class ExtensionValidatorTest {

    private ExtensionValidator extensionValidator = new ExtensionValidator();

    @Test
    void expected_extension_does_not_exist_test() {
        AuthenticationExtensionsClientOutputs<ExtensionClientOutput> clientOutputs = new AuthenticationExtensionsClientOutputs<>();
        Map<String, ExtensionAuthenticatorOutput> authenticatorOutputs = new HashMap<>();
        authenticatorOutputs.put(SupportedExtensionsExtensionAuthenticatorOutput.ID,
                new SupportedExtensionsExtensionAuthenticatorOutput(Collections.singletonList(SupportedExtensionsExtensionClientOutput.ID)));
        List<String> expectedExtensions = Arrays.asList(FIDOAppIDExtensionClientOutput.ID, SupportedExtensionsExtensionAuthenticatorOutput.ID);
        extensionValidator.validate(clientOutputs, new AuthenticationExtensionsAuthenticatorOutputs<>(authenticatorOutputs), expectedExtensions);
    }

    @Test
    void expected_extension_does_exist_test() {
        Map<String, ExtensionClientOutput> clientOutputs = new HashMap<>();
        AuthenticationExtensionsAuthenticatorOutputs<ExtensionAuthenticatorOutput> authenticatorOutputs = new AuthenticationExtensionsAuthenticatorOutputs<>();
        clientOutputs.put(FIDOAppIDExtensionClientOutput.ID, new FIDOAppIDExtensionClientOutput(true));
        List<String> expectedExtensions = Collections.singletonList(FIDOAppIDExtensionClientOutput.ID);
        extensionValidator.validate(new AuthenticationExtensionsClientOutputs<>(clientOutputs), authenticatorOutputs, expectedExtensions);
    }

    @Test
    void unexpected_extension_does_exist_test() {
        Map<String, ExtensionClientOutput> clientOutputs = new HashMap<>();
        AuthenticationExtensionsAuthenticatorOutputs<ExtensionAuthenticatorOutput> authenticatorOutputs = new AuthenticationExtensionsAuthenticatorOutputs<>();
        clientOutputs.put(FIDOAppIDExtensionClientOutput.ID, new FIDOAppIDExtensionClientOutput(true));
        List<String> expectedExtensions = Collections.emptyList();
        assertThrows(UnexpectedExtensionException.class,
                () -> extensionValidator.validate(new AuthenticationExtensionsClientOutputs<>(clientOutputs), authenticatorOutputs, expectedExtensions)
        );
    }

    @Test
    void unexpected_authenticator_extension_does_exist_test() {
        AuthenticationExtensionsClientOutputs<ExtensionClientOutput> clientOutputs = new AuthenticationExtensionsClientOutputs<>();
        Map<String, ExtensionAuthenticatorOutput> authenticatorOutputs = new HashMap<>();
        authenticatorOutputs.put(SupportedExtensionsExtensionAuthenticatorOutput.ID,
                new SupportedExtensionsExtensionAuthenticatorOutput(Collections.singletonList(SupportedExtensionsExtensionClientOutput.ID)));
        List<String> expectedExtensions = Collections.emptyList();
        assertThrows(UnexpectedExtensionException.class,
                () -> extensionValidator.validate(clientOutputs, new AuthenticationExtensionsAuthenticatorOutputs<>(authenticatorOutputs), expectedExtensions)
        );
    }

    @Test
    void expectedExtensions_null_test() {
        AuthenticationExtensionsClientOutputs<ExtensionClientOutput> clientOutputs = new AuthenticationExtensionsClientOutputs<>();
        Map<String, ExtensionAuthenticatorOutput> authenticatorOutputs = new HashMap<>();
        authenticatorOutputs.put(SupportedExtensionsExtensionAuthenticatorOutput.ID,
                new SupportedExtensionsExtensionAuthenticatorOutput(Collections.singletonList(SupportedExtensionsExtensionClientOutput.ID)));
        extensionValidator.validate(clientOutputs, new AuthenticationExtensionsAuthenticatorOutputs<>(authenticatorOutputs), null);
    }

    @Test
    void clientOutputs_and_authenticatorOutputs_null_test() {
        extensionValidator.validate(null, null, null);
    }
}