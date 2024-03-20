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

package com.webauthn4j.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.CollectionUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Options for Credential Creation
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#dictdef-publickeycredentialcreationoptions">
 * §5.4. Options for Credential Creation (dictionary PublicKeyCredentialCreationOptions)</a>
 */
public class PublicKeyCredentialCreationOptions {

    // ~ Instance fields
    // ================================================================================================

    private final PublicKeyCredentialRpEntity rp;
    private final PublicKeyCredentialUserEntity user;

    private final Challenge challenge;
    private final List<PublicKeyCredentialParameters> pubKeyCredParams;
    private final Long timeout;
    private final List<PublicKeyCredentialDescriptor> excludeCredentials;
    private final AuthenticatorSelectionCriteria authenticatorSelection;
    private final AttestationConveyancePreference attestation;
    private final AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions;

    @SuppressWarnings("squid:S00107")
    @JsonCreator
    public PublicKeyCredentialCreationOptions(
            @NonNull @JsonProperty("rp") PublicKeyCredentialRpEntity rp,
            @NonNull @JsonProperty("user") PublicKeyCredentialUserEntity user,
            @NonNull @JsonProperty("challenge") Challenge challenge,
            @NonNull @JsonProperty("pubKeyCredParams") List<PublicKeyCredentialParameters> pubKeyCredParams,
            @Nullable @JsonProperty("timeout") Long timeout,
            @Nullable @JsonProperty("excludeCredentials") List<PublicKeyCredentialDescriptor> excludeCredentials,
            @Nullable @JsonProperty("authenticatorSelection") AuthenticatorSelectionCriteria authenticatorSelection,
            @Nullable @JsonProperty("attestation") AttestationConveyancePreference attestation,
            @Nullable @JsonProperty("extensions") AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions) {
        AssertUtil.notNull(rp, "rp must not be null");
        AssertUtil.notNull(user, "user must not be null");
        AssertUtil.notNull(challenge, "challenge must not be null");
        AssertUtil.notNull(pubKeyCredParams, "pubKeyCredParams must not be null");
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
            @NonNull PublicKeyCredentialRpEntity rp,
            @NonNull PublicKeyCredentialUserEntity user,
            @NonNull Challenge challenge,
            @NonNull List<PublicKeyCredentialParameters> pubKeyCredParams) {
        this(rp, user, challenge, pubKeyCredParams, null, Collections.emptyList(), null, null, null);
    }

    public @NonNull PublicKeyCredentialRpEntity getRp() {
        return rp;
    }

    public @NonNull PublicKeyCredentialUserEntity getUser() {
        return user;
    }

    public @NonNull Challenge getChallenge() {
        return challenge;
    }

    public @NonNull List<PublicKeyCredentialParameters> getPubKeyCredParams() {
        return pubKeyCredParams;
    }

    public @Nullable Long getTimeout() {
        return timeout;
    }

    public @Nullable List<PublicKeyCredentialDescriptor> getExcludeCredentials() {
        return excludeCredentials;
    }

    public @Nullable AuthenticatorSelectionCriteria getAuthenticatorSelection() {
        return authenticatorSelection;
    }

    public @Nullable AttestationConveyancePreference getAttestation() {
        return attestation;
    }

    public @Nullable AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> getExtensions() {
        return extensions;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PublicKeyCredentialCreationOptions that = (PublicKeyCredentialCreationOptions) o;
        return Objects.equals(rp, that.rp) && Objects.equals(user, that.user) && Objects.equals(challenge, that.challenge) && Objects.equals(pubKeyCredParams, that.pubKeyCredParams) && Objects.equals(timeout, that.timeout) && Objects.equals(excludeCredentials, that.excludeCredentials) && Objects.equals(authenticatorSelection, that.authenticatorSelection) && Objects.equals(attestation, that.attestation) && Objects.equals(extensions, that.extensions);
    }

    @Override
    public int hashCode() {

        return Objects.hash(rp, user, challenge, pubKeyCredParams, timeout, excludeCredentials, authenticatorSelection, attestation, extensions);
    }

    @Override
    public String toString() {
        return "PublicKeyCredentialCreationOptions(" +
                "rp=" + rp +
                ", user=" + user +
                ", challenge=" + challenge +
                ", pubKeyCredParams=" + pubKeyCredParams +
                ", timeout=" + timeout +
                ", excludeCredentials=" + excludeCredentials +
                ", authenticatorSelection=" + authenticatorSelection +
                ", attestation=" + attestation +
                ", extensions=" + extensions +
                ')';
    }
}
