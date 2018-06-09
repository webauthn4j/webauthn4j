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
import com.webauthn4j.extension.authneticator.AuthenticatorExtensionOutput;
import com.webauthn4j.util.WIP;

import java.util.List;
import java.util.Map;

@WIP
public class PublicKeyCredentialRequestOptions {

    private Challenge challenge;
    private long timeout;
    private String rpId;
    private List<PublicKeyCredentialDescriptor> allowCredentials;
    private UserVerificationRequirement userVerification;
    private Map<String, AuthenticatorExtensionOutput> extensions;

    public PublicKeyCredentialRequestOptions(Challenge challenge,
                                             long timeout,
                                             String rpId,
                                             List<PublicKeyCredentialDescriptor> allowCredentials,
                                             UserVerificationRequirement userVerification,
                                             Map<String, AuthenticatorExtensionOutput> extensions) {
        this.challenge = challenge;
        this.timeout = timeout;
        this.rpId = rpId;
        this.allowCredentials = allowCredentials;
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

    public Map<String, AuthenticatorExtensionOutput> getExtensions() {
        return extensions;
    }
}
