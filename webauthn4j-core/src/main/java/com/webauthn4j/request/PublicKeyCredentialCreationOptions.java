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

package com.webauthn4j.request;

import com.webauthn4j.response.client.challenge.Challenge;
import com.webauthn4j.request.extension.client.ClientExtensionInput;
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

    public PublicKeyCredentialCreationOptions(
            PublicKeyCredentialRpEntity rp,
            PublicKeyCredentialUserEntity user,
            Challenge challenge,
            List<PublicKeyCredentialParameters> pubKeyCredParams,
            BigInteger timeout,
            List<PublicKeyCredentialDescriptor> excludeCredentials,
            AuthenticatorSelectionCriteria authenticatorSelection,
            AttestationConveyancePreference attestation,
            Map<String, ClientExtensionInput> extensions) {
        this.rp = rp;
        this.user = user;
        this.challenge = challenge;
        this.pubKeyCredParams = pubKeyCredParams;
        this.timeout = timeout;
        this.excludeCredentials = excludeCredentials;
        this.authenticatorSelection = authenticatorSelection;
        this.attestation = attestation;
        this.extensions = extensions;
    }

    public PublicKeyCredentialCreationOptions(PublicKeyCredentialRpEntity rp, PublicKeyCredentialUserEntity user, Challenge challenge, List<PublicKeyCredentialParameters> pubKeyCredParams) {
        this(rp, user, challenge, pubKeyCredParams, null, Collections.emptyList(), null, null, Collections.emptyMap());
    }

    public PublicKeyCredentialRpEntity getRp() {
        return rp;
    }

    public PublicKeyCredentialUserEntity getUser() {
        return user;
    }

    public Challenge getChallenge() {
        return challenge;
    }

    public List<PublicKeyCredentialParameters> getPubKeyCredParams() {
        return pubKeyCredParams;
    }

    public BigInteger getTimeout() {
        return timeout;
    }

    public List<PublicKeyCredentialDescriptor> getExcludeCredentials() {
        return excludeCredentials;
    }

    public AuthenticatorSelectionCriteria getAuthenticatorSelection() {
        return authenticatorSelection;
    }

    public AttestationConveyancePreference getAttestation() {
        return attestation;
    }

    public Map<String, ClientExtensionInput> getExtensions() {
        return extensions;
    }
}
