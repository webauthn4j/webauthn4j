package com.webauthn4j.test.authenticator.model;

import com.webauthn4j.test.platform.*;

import java.util.List;

public class MakeCredentialRequest {

    private byte[] clientDataHash;
    private PublicKeyCredentialRpEntity rpEntity;
    private PublicKeyCredentialUserEntity userEntity;
    private boolean requireResidentKey;
    private boolean requireUserPresence;
    private boolean requireUserVerification;
    private List<PublicKeyCredentialParameters> credTypesAndPublicKeyAlgs;
    private List<PublicKeyCredentialDescriptor> excludeCredentialDescriptorList;
    private AuthenticationExtensionsClientInputs extensions;

    public byte[] getClientDataHash() {
        return clientDataHash;
    }

    public void setClientDataHash(byte[] clientDataHash) {
        this.clientDataHash = clientDataHash;
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
        this.credTypesAndPublicKeyAlgs = credTypesAndPublicKeyAlgs;
    }

    public List<PublicKeyCredentialDescriptor> getExcludeCredentialDescriptorList() {
        return excludeCredentialDescriptorList;
    }

    public void setExcludeCredentialDescriptorList(List<PublicKeyCredentialDescriptor> excludeCredentialDescriptorList) {
        this.excludeCredentialDescriptorList = excludeCredentialDescriptorList;
    }

    public AuthenticationExtensionsClientInputs getExtensions() {
        return extensions;
    }

    public void setExtensions(AuthenticationExtensionsClientInputs extensions) {
        this.extensions = extensions;
    }
}
