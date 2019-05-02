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

package com.webauthn4j.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.util.CollectionUtil;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Options for Credential Creation
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#dictdef-publickeycredentialcreationoptions">
 * §5.4. Options for Credential Creation (dictionary PublicKeyCredentialCreationOptions)</a>
 */
public class PublicKeyCredentialCreationOptions implements Serializable {

    // ~ Instance fields
    // ================================================================================================

    private PublicKeyCredentialRpEntity rp;
    private PublicKeyCredentialUserEntity user;

    private Challenge challenge;
    private List<PublicKeyCredentialParameters> pubKeyCredParams = Collections.emptyList();
    private Long timeout;
    private List<PublicKeyCredentialDescriptor> excludeCredentials = Collections.emptyList();
    private AuthenticatorSelectionCriteria authenticatorSelection;
    private AttestationConveyancePreference attestation;
    private AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions;

    @SuppressWarnings("squid:S00107")
    @JsonCreator
    public PublicKeyCredentialCreationOptions(
            @JsonProperty("rp") PublicKeyCredentialRpEntity rp,
            @JsonProperty("user") PublicKeyCredentialUserEntity user,
            @JsonProperty("challenge") Challenge challenge,
            @JsonProperty("pubKeyCredParams") List<PublicKeyCredentialParameters> pubKeyCredParams,
            @JsonProperty("timeout") Long timeout,
            @JsonProperty("excludeCredentials") List<PublicKeyCredentialDescriptor> excludeCredentials,
            @JsonProperty("authenticatorSelection") AuthenticatorSelectionCriteria authenticatorSelection,
            @JsonProperty("attestation") AttestationConveyancePreference attestation,
            @JsonProperty("extensions") AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions) {
        this.rp = rp;
        this.user = user;
        this.challenge = challenge;
        this.pubKeyCredParams = CollectionUtil.unmodifiableList(pubKeyCredParams);
        this.timeout = timeout;
        this.excludeCredentials = CollectionUtil.unmodifiableList(excludeCredentials);
        this.authenticatorSelection = authenticatorSelection;
        this.attestation = attestation;
        this.extensions = extensions;
    }

    public PublicKeyCredentialCreationOptions(
            PublicKeyCredentialRpEntity rp,
            PublicKeyCredentialUserEntity user,
            Challenge challenge,
            List<PublicKeyCredentialParameters> pubKeyCredParams) {
        this(rp, user, challenge, pubKeyCredParams, null, Collections.emptyList(), null, null, null);
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

    public Long getTimeout() {
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

    public AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> getExtensions() {
        return extensions;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PublicKeyCredentialCreationOptions that = (PublicKeyCredentialCreationOptions) o;
        return Objects.equals(rp, that.rp) &&
                Objects.equals(user, that.user) &&
                Objects.equals(challenge, that.challenge) &&
                Objects.equals(pubKeyCredParams, that.pubKeyCredParams) &&
                Objects.equals(timeout, that.timeout) &&
                Objects.equals(excludeCredentials, that.excludeCredentials) &&
                Objects.equals(authenticatorSelection, that.authenticatorSelection) &&
                attestation == that.attestation &&
                Objects.equals(extensions, that.extensions);
    }

    @Override
    public int hashCode() {

        return Objects.hash(rp, user, challenge, pubKeyCredParams, timeout, excludeCredentials, authenticatorSelection, attestation, extensions);
    }
}
