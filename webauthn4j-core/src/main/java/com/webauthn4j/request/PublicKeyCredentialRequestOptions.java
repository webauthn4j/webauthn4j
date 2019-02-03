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

import com.webauthn4j.request.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.response.client.challenge.Challenge;
import com.webauthn4j.util.WIP;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

@WIP
public class PublicKeyCredentialRequestOptions implements Serializable {

    // ~ Instance fields
    // ================================================================================================

    private Challenge challenge;
    private long timeout;
    private String rpId;
    private List<PublicKeyCredentialDescriptor> allowCredentials;
    private UserVerificationRequirement userVerification;
    private AuthenticationExtensionsClientInputs extensions;

    public PublicKeyCredentialRequestOptions(Challenge challenge,
                                             long timeout,
                                             String rpId,
                                             List<PublicKeyCredentialDescriptor> allowCredentials,
                                             UserVerificationRequirement userVerification,
                                             AuthenticationExtensionsClientInputs extensions) {
        this.challenge = challenge;
        this.timeout = timeout;
        this.rpId = rpId;
        this.allowCredentials = Collections.unmodifiableList(allowCredentials);
        this.userVerification = userVerification;
        this.extensions = extensions;
    }

    public Challenge getChallenge() {
        return challenge;
    }

    public long getTimeout() {
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

    public AuthenticationExtensionsClientInputs getExtensions() {
        return extensions;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PublicKeyCredentialRequestOptions that = (PublicKeyCredentialRequestOptions) o;
        return timeout == that.timeout &&
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
