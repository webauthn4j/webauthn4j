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
import com.webauthn4j.appattest.authenticator.DCAppleDeviceImpl;
import com.webauthn4j.authenticator.CoreAuthenticator;
import com.webauthn4j.data.CoreAuthenticationData;
import com.webauthn4j.data.CoreAuthenticationParameters;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.server.CoreServerProperty;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.verifier.CoreAuthenticationDataVerifier;
import com.webauthn4j.verifier.CoreAuthenticationObject;
import com.webauthn4j.verifier.CustomCoreAuthenticationVerifier;
import org.jetbrains.annotations.NotNull;

import java.util.List;

public class DCAssertionDataVerifier extends CoreAuthenticationDataVerifier {

    public DCAssertionDataVerifier(List<CustomCoreAuthenticationVerifier> customAuthenticationValidators) {
        super(customAuthenticationValidators, new DCAssertionSignatureVerifier());
    }

    @Override
    protected @NotNull CoreAuthenticationObject createCoreAuthenticationObject(@NotNull CoreAuthenticationData authenticationData, @NotNull CoreAuthenticationParameters authenticationParameters) {

        AssertUtil.notNull(authenticationData, "authenticationData must not be null");
        AssertUtil.notNull(authenticationData, "authenticationParameters must not be null");

        byte[] credentialId = authenticationData.getCredentialId();
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = authenticationData.getAuthenticatorData();
        byte[] authenticatorDataBytes = authenticationData.getAuthenticatorDataBytes();
        byte[] clientDataHash = authenticationData.getClientDataHash();

        CoreServerProperty serverProperty = authenticationParameters.getServerProperty();
        CoreAuthenticator authenticator = authenticationParameters.getAuthenticator();
        DCAppleDevice dcAppleDevice = new DCAppleDeviceImpl(
                authenticator.getAttestedCredentialData(),
                authenticator.getAttestationStatement(),
                authenticator.getCounter(),
                authenticator.getAuthenticatorExtensions());

        //noinspection ConstantConditions null check is already done in caller
        return new DCAuthenticationObject(
                credentialId, authenticatorData, authenticatorDataBytes, clientDataHash, serverProperty, dcAppleDevice
        );
    }

}
