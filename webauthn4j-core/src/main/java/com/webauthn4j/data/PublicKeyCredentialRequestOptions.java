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
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.CollectionUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.List;
import java.util.Objects;

/**
 * {@link PublicKeyCredentialRequestOptions} supplies get() with the data it needs to
 * generate an assertion. Its challenge member MUST be present, while its other members are OPTIONAL.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#dictdef-publickeycredentialrequestoptions">
 * §5.5. Options for Assertion Generation (dictionary PublicKeyCredentialRequestOptions)</a>
 */
public class PublicKeyCredentialRequestOptions {

    // ~ Instance fields
    // ================================================================================================

    private final Challenge challenge;
    private final Long timeout;
    private final String rpId;
    private final List<PublicKeyCredentialDescriptor> allowCredentials;
    private final UserVerificationRequirement userVerification;
    private final AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> extensions;

    @JsonCreator
    public PublicKeyCredentialRequestOptions(@NonNull @JsonProperty("challenge") Challenge challenge,
                                             @Nullable @JsonProperty("timeout") Long timeout,
                                             @Nullable @JsonProperty("rpId") String rpId,
                                             @Nullable @JsonProperty("allowCredentials") List<PublicKeyCredentialDescriptor> allowCredentials,
                                             @Nullable @JsonProperty("userVerification") UserVerificationRequirement userVerification,
                                             @Nullable @JsonProperty("extensions") AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> extensions) {
        AssertUtil.notNull(challenge, "challenge must not be null");
        this.challenge = challenge;
        this.timeout = timeout;
        this.rpId = rpId;
        this.allowCredentials = CollectionUtil.unmodifiableList(allowCredentials);
        this.userVerification = userVerification;
        this.extensions = extensions;
    }

    public @NonNull Challenge getChallenge() {
        return challenge;
    }

    public @Nullable Long getTimeout() {
        return timeout;
    }

    public @Nullable String getRpId() {
        return rpId;
    }

    public @Nullable List<PublicKeyCredentialDescriptor> getAllowCredentials() {
        return allowCredentials;
    }

    public @Nullable UserVerificationRequirement getUserVerification() {
        return userVerification;
    }

    public @Nullable AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> getExtensions() {
        return extensions;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PublicKeyCredentialRequestOptions that = (PublicKeyCredentialRequestOptions) o;
        return Objects.equals(challenge, that.challenge) && Objects.equals(timeout, that.timeout) && Objects.equals(rpId, that.rpId) && Objects.equals(allowCredentials, that.allowCredentials) && Objects.equals(userVerification, that.userVerification) && Objects.equals(extensions, that.extensions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(challenge, timeout, rpId, allowCredentials, userVerification, extensions);
    }

    @Override
    public String toString() {
        return "PublicKeyCredentialRequestOptions(" +
                "challenge=" + challenge +
                ", timeout=" + timeout +
                ", rpId=" + rpId +
                ", allowCredentials=" + allowCredentials +
                ", userVerification=" + userVerification +
                ", extensions=" + extensions +
                ')';
    }
}
