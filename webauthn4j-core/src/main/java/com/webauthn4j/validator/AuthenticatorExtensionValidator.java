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
import com.webauthn4j.validator.exception.UnexpectedExtensionException;

import java.util.List;

/**
 * Validates authenticatorExtensionOutputs
 */
class AuthenticatorExtensionValidator {

    // ~ Methods
    // ========================================================================================================

    public <A extends ExtensionAuthenticatorOutput> void validate(AuthenticationExtensionsAuthenticatorOutputs<A> authenticationExtensionsAuthenticatorOutputs,
                                                                                                   List<String> expectedExtensionIdentifiers) {
        validateExtensionIds(authenticationExtensionsAuthenticatorOutputs, expectedExtensionIdentifiers);
    }

    //TODO: extensionId -> key
    private <A extends ExtensionAuthenticatorOutput> void validateExtensionIds(AuthenticationExtensionsAuthenticatorOutputs<A> authenticationExtensionsAuthenticatorOutputs, List<String> expectedExtensionIdentifiers) {
        List<String> expected;
        if (expectedExtensionIdentifiers == null) {
            return;
        } else {
            expected = expectedExtensionIdentifiers;
        }

        if (authenticationExtensionsAuthenticatorOutputs != null) {
            authenticationExtensionsAuthenticatorOutputs.getKeys().forEach(key -> {
                if (!expected.contains(key)) {
                    throw new UnexpectedExtensionException(String.format("Unexpected authenticator extension '%s' is contained", key));
                }
            });
        }
    }

}
