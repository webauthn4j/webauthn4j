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

package com.webauthn4j.verifier;

import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import org.junit.jupiter.api.Test;

@SuppressWarnings("ConstantConditions")
class AuthenticatorExtensionVerifierTest {

    private final AuthenticatorExtensionVerifier extensionValidator = new AuthenticatorExtensionVerifier();

    @Test
    void test() {
        AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration builder = new AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration();
        builder.set("test", true);
        extensionValidator.verify(builder.build());
    }

    @Test
    void authenticatorOutputs_null_test() {
        extensionValidator.verify(null);
    }

}