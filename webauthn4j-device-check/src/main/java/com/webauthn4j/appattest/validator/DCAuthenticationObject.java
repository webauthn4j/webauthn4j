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

package com.webauthn4j.appattest.validator;

import com.webauthn4j.appattest.authenticator.DCAppleDevice;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.server.CoreServerProperty;
import com.webauthn4j.validator.CoreAuthenticationObject;
import org.checkerframework.checker.nullness.qual.NonNull;

public class DCAuthenticationObject extends CoreAuthenticationObject {
    public DCAuthenticationObject(
            @NonNull byte[] credentialId,
            @NonNull AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData,
            @NonNull byte[] authenticatorDataBytes,
            @NonNull byte[] clientDataHash,
            @NonNull CoreServerProperty serverProperty,
            @NonNull DCAppleDevice dcAppleDevice) {
        super(credentialId, authenticatorData, authenticatorDataBytes, clientDataHash, serverProperty, dcAppleDevice);
    }
}
