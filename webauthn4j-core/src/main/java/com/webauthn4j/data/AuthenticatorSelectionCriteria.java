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
import org.checkerframework.checker.nullness.qual.Nullable;

import java.io.Serializable;
import java.util.Objects;

/**
 * WebAuthn Relying Parties may use the AuthenticatorSelectionCriteria to specify their
 * requirements regarding authenticator attributes.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#dictdef-authenticatorselectioncriteria">
 * §5.4.4. Authenticator Selection Criteria (dictionary AuthenticatorSelectionCriteria)</a>
 */
public class AuthenticatorSelectionCriteria implements Serializable {

    // ~ Instance fields
    // ================================================================================================

    private final AuthenticatorAttachment authenticatorAttachment;

    @SuppressWarnings("UnusedAssignment")
    private boolean requireResidentKey = false;

    private ResidentKeyRequirement residentKey = null;

    @SuppressWarnings("UnusedAssignment")
    private UserVerificationRequirement userVerification = UserVerificationRequirement.PREFERRED;

    /**
     * Constructor for Jackson deserializer
     * @param authenticatorAttachment authenticator attachment
     * @param requireResidentKey This describes resident key requirement if residentKey member is absent.
     * @param residentKey relying party's requirement for resident-key
     * @param userVerification relying party's requirement for user verification
     */
    @JsonCreator
    public AuthenticatorSelectionCriteria(
            @Nullable @JsonProperty("authenticatorAttachment") AuthenticatorAttachment authenticatorAttachment,
            @Nullable @JsonProperty("requireResidentKey") boolean requireResidentKey,
            @Nullable @JsonProperty("residentKey") ResidentKeyRequirement residentKey,
            @Nullable @JsonProperty("userVerification") UserVerificationRequirement userVerification) {
        this.authenticatorAttachment = authenticatorAttachment;
        this.requireResidentKey = requireResidentKey;
        this.residentKey = residentKey;
        this.userVerification = userVerification;
    }

    /**
     * Constructor for WebAuthn Level2 spec
     * @param authenticatorAttachment authenticator attachment
     * @param residentKey relying party's requirement for resident-key
     * @param userVerification relying party's requirement for user verification
     */
    public AuthenticatorSelectionCriteria(
            @Nullable AuthenticatorAttachment authenticatorAttachment,
            @Nullable ResidentKeyRequirement residentKey,
            @Nullable UserVerificationRequirement userVerification) {
        this(authenticatorAttachment, false, residentKey, userVerification);
    }

    /**
     * Constructor for WebAuthn Level1 spec backward-compatibility
     * @param authenticatorAttachment authenticator attachment
     * @param requireResidentKey This describes resident key requirement
     * @param userVerification relying party's requirement for user verification
     */
    public AuthenticatorSelectionCriteria(
            @Nullable AuthenticatorAttachment authenticatorAttachment,
            boolean requireResidentKey, //TODO: must not be primitive
            @Nullable UserVerificationRequirement userVerification) {
        this(authenticatorAttachment, requireResidentKey, null, userVerification);
    }

    public @Nullable AuthenticatorAttachment getAuthenticatorAttachment() {
        return authenticatorAttachment;
    }

    public boolean isRequireResidentKey() {
        return requireResidentKey;
    }

    public @Nullable ResidentKeyRequirement getResidentKey() {
        return residentKey;
    }

    public @Nullable UserVerificationRequirement getUserVerification() {
        return userVerification;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticatorSelectionCriteria that = (AuthenticatorSelectionCriteria) o;
        return requireResidentKey == that.requireResidentKey &&
                authenticatorAttachment == that.authenticatorAttachment &&
                residentKey == that.residentKey &&
                userVerification == that.userVerification;
    }

    @Override
    public int hashCode() {
        return Objects.hash(authenticatorAttachment, requireResidentKey, residentKey, userVerification);
    }
}
