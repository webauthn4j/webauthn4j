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

package net.sharplab.springframework.security.webauthn.authenticator;

import net.sharplab.springframework.security.webauthn.attestation.authenticator.WebAuthnAttestedCredentialData;
import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;
import net.sharplab.springframework.security.webauthn.userdetails.WebAuthnUserDetails;

/**
 * A {@link WebAuthnAuthenticator} implementation
 */
public class WebAuthnAuthenticatorImpl implements WebAuthnAuthenticator {

    //~ Instance fields ================================================================================================
    private String name;
    private WebAuthnUserDetails user;
    private WebAuthnAttestedCredentialData attestationData;
    private WebAuthnAttestationStatement attestationStatement;

    public WebAuthnAuthenticatorImpl(String name, WebAuthnUserDetails user, WebAuthnAttestedCredentialData attestationData, WebAuthnAttestationStatement attestationStatement) {
        this.name = name;
        this.user = user;
        this.attestationData = attestationData;
        this.attestationStatement = attestationStatement;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public WebAuthnUserDetails getUser() {
        return user;
    }

    @Override
    public WebAuthnAttestedCredentialData getAttestationData() {
        return attestationData;
    }

    @Override
    public WebAuthnAttestationStatement getAttestationStatement() {
        return attestationStatement;
    }

    @Override
    public String getFormat() {
        return attestationStatement.getFormat();
    }

}
