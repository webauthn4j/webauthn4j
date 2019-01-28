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

import com.webauthn4j.response.extension.authenticator.ExtensionAuthenticatorOutput;
import com.webauthn4j.response.extension.authenticator.ExtensionsAuthenticatorOutputs;
import com.webauthn4j.response.extension.client.ExtensionClientOutput;
import com.webauthn4j.response.extension.client.ExtensionsClientOutputs;
import com.webauthn4j.validator.exception.UnexpectedExtensionException;

import java.util.Collections;
import java.util.List;

/**
 * Validates clientExtensionOutputs and authenticatorExtensionOutputs
 */
public class ExtensionValidator {

    // ~ Methods
    // ========================================================================================================

    public void validate(ExtensionsClientOutputs<ExtensionClientOutput> extensionsClientOutputs,
                         ExtensionsAuthenticatorOutputs<ExtensionAuthenticatorOutput> extensionsAuthenticatorOutputs,
                         List<String> expectedExtensionIdentifiers) {
        List<String> expected;
        if (expectedExtensionIdentifiers == null) {
            expected = Collections.emptyList();
        } else {
            expected = expectedExtensionIdentifiers;
        }

        if (extensionsClientOutputs != null) {
            extensionsClientOutputs.keySet().forEach(identifier -> {
                if (!expected.contains(identifier)) {
                    throw new UnexpectedExtensionException(String.format("Unexpected client extension '%s' is contained", identifier));
                }
            });
        }
        if (extensionsAuthenticatorOutputs != null) {
            extensionsAuthenticatorOutputs.keySet().forEach(identifier -> {
                if (!expected.contains(identifier)) {
                    throw new UnexpectedExtensionException(String.format("Unexpected authenticator extension '%s' is contained", identifier));
                }
            });
        }
    }
}
