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

package com.webauthn4j.test.authenticator.webauthn;

import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialRpEntity;
import com.webauthn4j.data.PublicKeyCredentialUserEntity;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput;
import com.webauthn4j.util.AssertUtil;

import java.util.Collections;
import java.util.List;

public class MakeCredentialRequest {

    private byte[] hash;
    private PublicKeyCredentialRpEntity rpEntity;
    private PublicKeyCredentialUserEntity userEntity;
    private boolean requireResidentKey;
    private boolean requireUserPresence;
    private boolean requireUserVerification;
    private List<PublicKeyCredentialParameters> credTypesAndPublicKeyAlgs;
    private List<PublicKeyCredentialDescriptor> excludeCredentialDescriptorList;
    private AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions;

    public MakeCredentialRequest(
            byte[] hash,
            PublicKeyCredentialRpEntity rpEntity,
            PublicKeyCredentialUserEntity userEntity,
            boolean requireResidentKey,
            boolean requireUserPresence,
            boolean requireUserVerification,
            List<PublicKeyCredentialParameters> credTypesAndPublicKeyAlgs,
            List<PublicKeyCredentialDescriptor> excludeCredentialDescriptorList,
            AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions) {

        AssertUtil.notNull(credTypesAndPublicKeyAlgs, "credTypesAndPublicKeyAlgs must not be null");

        this.hash = hash;
        this.rpEntity = rpEntity;
        this.userEntity = userEntity;
        this.requireResidentKey = requireResidentKey;
        this.requireUserPresence = requireUserPresence;
        this.requireUserVerification = requireUserVerification;
        this.credTypesAndPublicKeyAlgs = credTypesAndPublicKeyAlgs;
        this.excludeCredentialDescriptorList = excludeCredentialDescriptorList;
        this.extensions = extensions;
    }

    public MakeCredentialRequest(
            byte[] hash,
            PublicKeyCredentialRpEntity rpEntity,
            PublicKeyCredentialUserEntity userEntity,
            boolean requireResidentKey,
            boolean requireUserPresence,
            boolean requireUserVerification,
            List<PublicKeyCredentialParameters> credTypesAndPublicKeyAlgs,
            List<PublicKeyCredentialDescriptor> excludeCredentialDescriptorList) {

        this(hash, rpEntity, userEntity, requireResidentKey, requireUserPresence, requireUserVerification, credTypesAndPublicKeyAlgs, excludeCredentialDescriptorList, new AuthenticationExtensionsClientInputs<>());
    }

    public MakeCredentialRequest(
            byte[] hash,
            PublicKeyCredentialRpEntity rpEntity,
            PublicKeyCredentialUserEntity userEntity,
            boolean requireResidentKey,
            boolean requireUserPresence,
            boolean requireUserVerification,
            List<PublicKeyCredentialParameters> credTypesAndPublicKeyAlgs) {

        this(hash, rpEntity, userEntity, requireResidentKey, requireUserPresence, requireUserVerification, credTypesAndPublicKeyAlgs, Collections.emptyList(), new AuthenticationExtensionsClientInputs<>());
    }


    public byte[] getHash() {
        return hash;
    }

    public void setHash(byte[] hash) {
        this.hash = hash;
    }

    public PublicKeyCredentialRpEntity getRpEntity() {
        return rpEntity;
    }

    public void setRpEntity(PublicKeyCredentialRpEntity rpEntity) {
        this.rpEntity = rpEntity;
    }

    public PublicKeyCredentialUserEntity getUserEntity() {
        return userEntity;
    }

    public void setUserEntity(PublicKeyCredentialUserEntity userEntity) {
        this.userEntity = userEntity;
    }

    public boolean isRequireResidentKey() {
        return requireResidentKey;
    }

    public void setRequireResidentKey(boolean requireResidentKey) {
        this.requireResidentKey = requireResidentKey;
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

    public List<PublicKeyCredentialParameters> getCredTypesAndPublicKeyAlgs() {
        return credTypesAndPublicKeyAlgs;
    }

    public void setCredTypesAndPublicKeyAlgs(List<PublicKeyCredentialParameters> credTypesAndPublicKeyAlgs) {
        AssertUtil.notNull(credTypesAndPublicKeyAlgs, "credTypesAndPublicKeyAlgs must not be null");
        this.credTypesAndPublicKeyAlgs = credTypesAndPublicKeyAlgs;
    }

    public List<PublicKeyCredentialDescriptor> getExcludeCredentialDescriptorList() {
        return excludeCredentialDescriptorList;
    }

    public void setExcludeCredentialDescriptorList(List<PublicKeyCredentialDescriptor> excludeCredentialDescriptorList) {
        this.excludeCredentialDescriptorList = excludeCredentialDescriptorList;
    }

    public AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> getExtensions() {
        return extensions;
    }

    public void setExtensions(AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput> extensions) {
        this.extensions = extensions;
    }
}
