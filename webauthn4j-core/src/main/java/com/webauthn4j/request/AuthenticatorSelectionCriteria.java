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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.util.Objects;

/**
 * WebAuthn Relying Parties may use the AuthenticatorSelectionCriteria dictionary to specify their
 * requirements regarding authenticator attributes.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#dictdef-authenticatorselectioncriteria">
 * §5.4.4. Authenticator Selection Criteria (dictionary AuthenticatorSelectionCriteria)</a>
 */
public class AuthenticatorSelectionCriteria implements Serializable {

    // ~ Instance fields
    // ================================================================================================

    private AuthenticatorAttachment authenticatorAttachment;

    @SuppressWarnings("UnusedAssignment")
    private boolean requireResidentKey = false;
    @SuppressWarnings("UnusedAssignment")
    private UserVerificationRequirement userVerification = UserVerificationRequirement.PREFERRED;

    @JsonCreator
    public AuthenticatorSelectionCriteria(
            @JsonProperty("authenticatorAttachment") AuthenticatorAttachment authenticatorAttachment,
            @JsonProperty("requireResidentKey") boolean requireResidentKey,
            @JsonProperty("userVerification") UserVerificationRequirement userVerification) {
        this.authenticatorAttachment = authenticatorAttachment;
        this.requireResidentKey = requireResidentKey;
        this.userVerification = userVerification;
    }

    public AuthenticatorAttachment getAuthenticatorAttachment() {
        return authenticatorAttachment;
    }

    public boolean isRequireResidentKey() {
        return requireResidentKey;
    }

    public UserVerificationRequirement getUserVerification() {
        return userVerification;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticatorSelectionCriteria that = (AuthenticatorSelectionCriteria) o;
        return requireResidentKey == that.requireResidentKey &&
                authenticatorAttachment == that.authenticatorAttachment &&
                userVerification == that.userVerification;
    }

    @Override
    public int hashCode() {

        return Objects.hash(authenticatorAttachment, requireResidentKey, userVerification);
    }
}
