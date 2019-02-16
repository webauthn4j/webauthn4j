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

import com.webauthn4j.response.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.response.extension.authenticator.ExtensionAuthenticatorOutput;
import com.webauthn4j.response.extension.authenticator.ExtensionsAuthenticatorOutputs;
import com.webauthn4j.response.extension.authenticator.SupportedExtensionsExtensionAuthenticatorOutput;
import com.webauthn4j.response.extension.client.ExtensionClientOutput;
import com.webauthn4j.response.extension.client.ExtensionsClientOutputs;
import com.webauthn4j.response.extension.client.FIDOAppIDExtensionClientOutput;
import com.webauthn4j.response.extension.client.SupportedExtensionsExtensionClientOutput;
import com.webauthn4j.validator.exception.UnexpectedExtensionException;
import org.junit.Test;

import java.util.*;

public class ExtensionValidatorTest {

    private ExtensionValidator extensionValidator = new ExtensionValidator();

    @Test
    public void expected_extension_does_not_exist_test(){
        ExtensionsClientOutputs<ExtensionClientOutput> clientOutputs = new ExtensionsClientOutputs<>();
        Map<String, ExtensionAuthenticatorOutput> authenticatorOutputs = new HashMap<>();
        authenticatorOutputs.put(SupportedExtensionsExtensionAuthenticatorOutput.ID,
                new SupportedExtensionsExtensionAuthenticatorOutput(Collections.singletonList(SupportedExtensionsExtensionClientOutput.ID)));
        List<String> expectedExtensions = Arrays.asList(FIDOAppIDExtensionClientOutput.ID, SupportedExtensionsExtensionAuthenticatorOutput.ID);
        extensionValidator.validate(clientOutputs, new AuthenticationExtensionsAuthenticatorOutputs<>(authenticatorOutputs), expectedExtensions);
    }

    @Test
    public void expected_extension_does_exist_test(){
        ExtensionsClientOutputs<ExtensionClientOutput> clientOutputs = new ExtensionsClientOutputs<>();
        ExtensionsAuthenticatorOutputs<ExtensionAuthenticatorOutput> authenticatorOutputs = new ExtensionsAuthenticatorOutputs<>();
        clientOutputs.put(FIDOAppIDExtensionClientOutput.ID, new FIDOAppIDExtensionClientOutput(true));
        List<String> expectedExtensions = Collections.singletonList(FIDOAppIDExtensionClientOutput.ID);
        extensionValidator.validate(clientOutputs, authenticatorOutputs, expectedExtensions);
    }

    @Test(expected = UnexpectedExtensionException.class)
    public void unexpected_extension_does_exist_test(){
        ExtensionsClientOutputs<ExtensionClientOutput> clientOutputs = new ExtensionsClientOutputs<>();
        ExtensionsAuthenticatorOutputs<ExtensionAuthenticatorOutput> authenticatorOutputs = new ExtensionsAuthenticatorOutputs<>();
        clientOutputs.put(FIDOAppIDExtensionClientOutput.ID, new FIDOAppIDExtensionClientOutput(true));
        List<String> expectedExtensions = Collections.emptyList();
        extensionValidator.validate(clientOutputs, authenticatorOutputs, expectedExtensions);
    }

    @Test(expected = UnexpectedExtensionException.class)
    public void unexpected_authenticator_extension_does_exist_test(){
        ExtensionsClientOutputs<ExtensionClientOutput> clientOutputs = new ExtensionsClientOutputs<>();
        Map<String, ExtensionAuthenticatorOutput> authenticatorOutputs = new HashMap<>();
        authenticatorOutputs.put(SupportedExtensionsExtensionAuthenticatorOutput.ID,
                new SupportedExtensionsExtensionAuthenticatorOutput(Collections.singletonList(SupportedExtensionsExtensionClientOutput.ID)));
        List<String> expectedExtensions = Collections.emptyList();
        extensionValidator.validate(clientOutputs, new AuthenticationExtensionsAuthenticatorOutputs<>(authenticatorOutputs), expectedExtensions);
    }


    @Test
    public void expectedExtensions_null_test(){
        ExtensionsClientOutputs<ExtensionClientOutput> clientOutputs = new ExtensionsClientOutputs<>();
        ExtensionsAuthenticatorOutputs<ExtensionAuthenticatorOutput> authenticatorOutputs = new ExtensionsAuthenticatorOutputs<>();
        extensionValidator.validate(clientOutputs, authenticatorOutputs, null);
    }

    @Test
    public void clientOutputs_and_authenticatorOutputs_null_test(){
        extensionValidator.validate(null, null, null);
    }


}