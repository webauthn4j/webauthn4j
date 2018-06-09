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

import com.webauthn4j.extension.authneticator.AuthenticatorExtensionOutput;
import com.webauthn4j.extension.client.ClientExtensionOutput;
import com.webauthn4j.validator.exception.UnexpectedExtensionException;

import java.util.List;
import java.util.Map;

public class ExtensionValidator {

    public void validate(Map<String, ClientExtensionOutput> clientExtensionOutputs,
                         Map<String, AuthenticatorExtensionOutput> authenticatorExtensionOutputs,
                         List<String> expectedExtensionIdentifiers) {
        if (clientExtensionOutputs != null) {
            clientExtensionOutputs.keySet().forEach(identifier -> {
                if (!expectedExtensionIdentifiers.contains(identifier)) {
                    throw new UnexpectedExtensionException(String.format("Unexpected client extension '%s' is contained", identifier));
                }
            });
        }
        if (authenticatorExtensionOutputs != null) {
            authenticatorExtensionOutputs.keySet().forEach(identifier -> {
                if (!expectedExtensionIdentifiers.contains(identifier)) {
                    throw new UnexpectedExtensionException(String.format("Unexpected authenticator extension '%s' is contained", identifier));
                }
            });
        }
    }
}
