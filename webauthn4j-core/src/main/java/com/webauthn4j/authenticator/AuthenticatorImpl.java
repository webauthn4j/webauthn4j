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

package com.webauthn4j.authenticator;

import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;

import java.util.Collections;
import java.util.Objects;
import java.util.Set;

/**
 * An {@link Authenticator} implementation
 */
public class AuthenticatorImpl extends CoreAuthenticatorImpl implements Authenticator {

    //~ Instance fields ================================================================================================
    private AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions;

    public AuthenticatorImpl(AttestedCredentialData attestedCredentialData, AttestationStatement attestationStatement, long counter, Set<AuthenticatorTransport> transports,
                             AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions,
                             AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorExtensions) {
        super(attestedCredentialData, attestationStatement, counter, transports, authenticatorExtensions);
        this.clientExtensions = clientExtensions;
    }

    public AuthenticatorImpl(AttestedCredentialData attestedCredentialData, AttestationStatement attestationStatement, long counter, Set<AuthenticatorTransport> transports) {
        this(attestedCredentialData, attestationStatement, counter, transports, new AuthenticationExtensionsClientOutputs<>(), new AuthenticationExtensionsAuthenticatorOutputs<>());
    }

    public AuthenticatorImpl(AttestedCredentialData attestedCredentialData, AttestationStatement attestationStatement, long counter) {
        this(attestedCredentialData, attestationStatement, counter, Collections.emptySet());
    }

    public static AuthenticatorImpl createFromRegistrationData(RegistrationData registrationData){
        return new AuthenticatorImpl(
                registrationData.getAttestationObject().getAuthenticatorData().getAttestedCredentialData(),
                registrationData.getAttestationObject().getAttestationStatement(),
                registrationData.getAttestationObject().getAuthenticatorData().getSignCount(),
                registrationData.getTransports());
    }


    @Override
    public AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> getClientExtensions() {
        return clientExtensions;
    }

    public void setClientExtensions(AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions) {
        this.clientExtensions = clientExtensions;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        AuthenticatorImpl that = (AuthenticatorImpl) o;
        return Objects.equals(clientExtensions, that.clientExtensions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), clientExtensions);
    }
}
