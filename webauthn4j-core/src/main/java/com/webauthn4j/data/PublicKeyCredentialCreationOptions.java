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
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

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
    private final List<PublicKeyCredentialHints> hints;
    private final AttestationConveyancePreference attestation;
    private final AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions;

    @SuppressWarnings("squid:S00107")
    @JsonCreator
    public PublicKeyCredentialCreationOptions(
            @NotNull @JsonProperty("rp") PublicKeyCredentialRpEntity rp,
            @NotNull @JsonProperty("user") PublicKeyCredentialUserEntity user,
            @NotNull @JsonProperty("challenge") Challenge challenge,
            @NotNull @JsonProperty("pubKeyCredParams") List<PublicKeyCredentialParameters> pubKeyCredParams,
            @Nullable @JsonProperty("timeout") Long timeout,
            @Nullable @JsonProperty("excludeCredentials") List<PublicKeyCredentialDescriptor> excludeCredentials,
            @Nullable @JsonProperty("authenticatorSelection") AuthenticatorSelectionCriteria authenticatorSelection,
            @Nullable @JsonProperty("hints") List<PublicKeyCredentialHints> hints,
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
        this.hints = hints;
        this.attestation = attestation;
        this.extensions = extensions;
    }

    @SuppressWarnings("squid:S00107")
    public PublicKeyCredentialCreationOptions(
            @NotNull @JsonProperty("rp") PublicKeyCredentialRpEntity rp,
            @NotNull @JsonProperty("user") PublicKeyCredentialUserEntity user,
            @NotNull @JsonProperty("challenge") Challenge challenge,
            @NotNull @JsonProperty("pubKeyCredParams") List<PublicKeyCredentialParameters> pubKeyCredParams,
            @Nullable @JsonProperty("timeout") Long timeout,
            @Nullable @JsonProperty("excludeCredentials") List<PublicKeyCredentialDescriptor> excludeCredentials,
            @Nullable @JsonProperty("authenticatorSelection") AuthenticatorSelectionCriteria authenticatorSelection,
            @Nullable @JsonProperty("attestation") AttestationConveyancePreference attestation,
            @Nullable @JsonProperty("extensions") AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions) {
        this(rp, user, challenge, pubKeyCredParams, timeout, excludeCredentials, authenticatorSelection, null, attestation, extensions);
    }

    public PublicKeyCredentialCreationOptions(
            @NotNull PublicKeyCredentialRpEntity rp,
            @NotNull PublicKeyCredentialUserEntity user,
            @NotNull Challenge challenge,
            @NotNull List<PublicKeyCredentialParameters> pubKeyCredParams) {
        this(rp, user, challenge, pubKeyCredParams, null, Collections.emptyList(), null, null, null, null);
    }

    public @NotNull PublicKeyCredentialRpEntity getRp() {
        return rp;
    }

    public @NotNull PublicKeyCredentialUserEntity getUser() {
        return user;
    }

    public @NotNull Challenge getChallenge() {
        return challenge;
    }

    public @NotNull List<PublicKeyCredentialParameters> getPubKeyCredParams() {
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

    public @Nullable List<PublicKeyCredentialHints> getHints() {
        return hints;
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
        return Objects.equals(rp, that.rp) && Objects.equals(user, that.user) && Objects.equals(challenge, that.challenge) && Objects.equals(pubKeyCredParams, that.pubKeyCredParams) && Objects.equals(timeout, that.timeout) && Objects.equals(excludeCredentials, that.excludeCredentials) && Objects.equals(authenticatorSelection, that.authenticatorSelection) && Objects.equals(hints, that.hints) && Objects.equals(attestation, that.attestation) && Objects.equals(extensions, that.extensions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(rp, user, challenge, pubKeyCredParams, timeout, excludeCredentials, authenticatorSelection, hints, attestation, extensions);
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
                ", hints=" + hints +
                ", attestation=" + attestation +
                ", extensions=" + extensions +
                ')';
    }
}
