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

package com.webauthn4j.test.client;

import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.util.WIP;

import java.math.BigInteger;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@WIP
public class PublicKeyCredentialCreationOptions {
    private PublicKeyCredentialRpEntity rp;
    private PublicKeyCredentialUserEntity user;

    private Challenge challenge;
    private List<PublicKeyCredentialParameters> pubKeyCredParams = Collections.emptyList();
    private BigInteger timeout;
    private List<PublicKeyCredentialDescriptor> excludeCredentials = Collections.emptyList();
    private AuthenticatorSelectionCriteria authenticatorSelection;
    private AttestationConveyancePreference attestation;
    private Map<String, ClientExtensionInput> extensions;


    public PublicKeyCredentialRpEntity getRp() {
        return rp;
    }

    public void setRp(PublicKeyCredentialRpEntity rp) {
        this.rp = rp;
    }

    public PublicKeyCredentialUserEntity getUser() {
        return user;
    }

    public void setUser(PublicKeyCredentialUserEntity user) {
        this.user = user;
    }

    public Challenge getChallenge() {
        return challenge;
    }

    public void setChallenge(Challenge challenge) {
        this.challenge = challenge;
    }

    public List<PublicKeyCredentialParameters> getPubKeyCredParams() {
        return pubKeyCredParams;
    }

    public void setPubKeyCredParams(List<PublicKeyCredentialParameters> pubKeyCredParams) {
        this.pubKeyCredParams = pubKeyCredParams;
    }

    public BigInteger getTimeout() {
        return timeout;
    }

    public void setTimeout(BigInteger timeout) {
        this.timeout = timeout;
    }

    public List<PublicKeyCredentialDescriptor> getExcludeCredentials() {
        return excludeCredentials;
    }

    public void setExcludeCredentials(List<PublicKeyCredentialDescriptor> excludeCredentials) {
        this.excludeCredentials = excludeCredentials;
    }

    public AuthenticatorSelectionCriteria getAuthenticatorSelection() {
        return authenticatorSelection;
    }

    public void setAuthenticatorSelection(AuthenticatorSelectionCriteria authenticatorSelection) {
        this.authenticatorSelection = authenticatorSelection;
    }

    public AttestationConveyancePreference getAttestation() {
        return attestation;
    }

    public void setAttestation(AttestationConveyancePreference attestation) {
        this.attestation = attestation;
    }

    public Map<String, ClientExtensionInput> getExtensions() {
        return extensions;
    }

    public void setExtensions(Map<String, ClientExtensionInput> extensions) {
        this.extensions = extensions;
    }
}
