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

import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.util.CollectionUtil;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;

/**
 * {@link PublicKeyCredentialRequestOptions} supplies get() with the data it needs to
 * generate an assertion. Its challenge member MUST be present, while its other members are OPTIONAL.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#dictdef-publickeycredentialrequestoptions">
 * §5.5. Options for Assertion Generation (dictionary PublicKeyCredentialRequestOptions)</a>
 */
public class PublicKeyCredentialRequestOptions implements Serializable {

    // ~ Instance fields
    // ================================================================================================

    private Challenge challenge;
    private Long timeout;
    private String rpId;
    private List<PublicKeyCredentialDescriptor> allowCredentials;
    private UserVerificationRequirement userVerification;
    private AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> extensions;

    public PublicKeyCredentialRequestOptions(Challenge challenge,
                                             Long timeout,
                                             String rpId,
                                             List<PublicKeyCredentialDescriptor> allowCredentials,
                                             UserVerificationRequirement userVerification,
                                             AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> extensions) {
        this.challenge = challenge;
        this.timeout = timeout;
        this.rpId = rpId;
        this.allowCredentials = CollectionUtil.unmodifiableList(allowCredentials);
        this.userVerification = userVerification;
        this.extensions = extensions;
    }

    public Challenge getChallenge() {
        return challenge;
    }

    public Long getTimeout() {
        return timeout;
    }

    public String getRpId() {
        return rpId;
    }

    public List<PublicKeyCredentialDescriptor> getAllowCredentials() {
        return allowCredentials;
    }

    public UserVerificationRequirement getUserVerification() {
        return userVerification;
    }

    public AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> getExtensions() {
        return extensions;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PublicKeyCredentialRequestOptions that = (PublicKeyCredentialRequestOptions) o;
        return Objects.equals(timeout, that.timeout) &&
                Objects.equals(challenge, that.challenge) &&
                Objects.equals(rpId, that.rpId) &&
                Objects.equals(allowCredentials, that.allowCredentials) &&
                userVerification == that.userVerification &&
                Objects.equals(extensions, that.extensions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(challenge, timeout, rpId, allowCredentials, userVerification, extensions);
    }
}
