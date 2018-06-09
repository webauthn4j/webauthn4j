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

package com.webauthn4j.test.authenticator.model;

import com.webauthn4j.extension.authneticator.AuthenticatorExtensionOutput;
import com.webauthn4j.test.client.PublicKeyCredentialDescriptor;

import java.util.List;
import java.util.Map;

public class GetAssertionRequest {

    private String rpId;
    private byte[] hash;
    private List<PublicKeyCredentialDescriptor> allowCredentialDescriptorList;
    private boolean requireUserPresence;
    private boolean requireUserVerification;
    private Map<String, AuthenticatorExtensionOutput> extensions;

    public String getRpId() {
        return rpId;
    }

    public void setRpId(String rpId) {
        this.rpId = rpId;
    }

    public byte[] getHash() {
        return hash;
    }

    public void setHash(byte[] hash) {
        this.hash = hash;
    }

    public List<PublicKeyCredentialDescriptor> getAllowCredentialDescriptorList() {
        return allowCredentialDescriptorList;
    }

    public void setAllowCredentialDescriptorList(List<PublicKeyCredentialDescriptor> allowCredentialDescriptorList) {
        this.allowCredentialDescriptorList = allowCredentialDescriptorList;
    }

    public boolean isRequireUserPresence() {
        return requireUserPresence;
    }

    public void setRequireUserPresence(boolean requireUserPresence) {
        this.requireUserPresence = requireUserPresence;
    }

    public boolean isRequireUserVerification() {
        return requireUserVerification;
    }

    public void setRequireUserVerification(boolean requireUserVerification) {
        this.requireUserVerification = requireUserVerification;
    }

    public Map<String, AuthenticatorExtensionOutput> getExtensions() {
        return extensions;
    }

    public void setExtensions(Map<String, AuthenticatorExtensionOutput> extensions) {
        this.extensions = extensions;
    }
}
