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
import com.webauthn4j.validator.CoreAuthenticationDataValidator;
import com.webauthn4j.validator.CoreAuthenticationObject;
import com.webauthn4j.validator.CustomCoreAuthenticationValidator;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.List;

public class DCAssertionDataValidator extends CoreAuthenticationDataValidator {

    public DCAssertionDataValidator(List<CustomCoreAuthenticationValidator> customAuthenticationValidators) {
        super(customAuthenticationValidators, new DCAssertionSignatureValidator());
    }

    @Override
    protected @NonNull CoreAuthenticationObject createCoreAuthenticationObject(@NonNull CoreAuthenticationData authenticationData, @NonNull CoreAuthenticationParameters authenticationParameters) {
        byte[] credentialId = authenticationData.getCredentialId();
        AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = authenticationData.getAuthenticatorData();
        byte[] authenticatorDataBytes = authenticationData.getAuthenticatorDataBytes();
        byte[] clientDataHash = authenticationData.getClientDataHash();

        CoreServerProperty serverProperty = authenticationParameters.getServerProperty();
        CoreAuthenticator authenticator = authenticationParameters.getAuthenticator();
        DCAppleDevice dcAppleDevice = new DCAppleDeviceImpl(
                authenticator.getAttestedCredentialData(),
                authenticator.getAttestationStatement(), //TODO: revisit
                authenticator.getCounter(),
                authenticator.getAuthenticatorExtensions());

        return new DCAuthenticationObject(
                credentialId, authenticatorData, authenticatorDataBytes, clientDataHash, serverProperty, dcAppleDevice
        );
    }

}
