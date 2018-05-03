package com.webauthn4j.test.authenticator.model;

import com.webauthn4j.attestation.authenticator.extension.Extension;
import com.webauthn4j.attestation.authenticator.extension.ExtensionIdentifier;
import com.webauthn4j.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.test.platform.PublicKeyCredentialDescriptor;
import com.webauthn4j.test.platform.PublicKeyCredentialRpEntity;
import com.webauthn4j.test.platform.PublicKeyCredentialType;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MakeCredentialRequest {

    private byte[] clientDataHash;
    private PublicKeyCredentialRpEntity rpEntity;
    private boolean requireResidentKey;
    private boolean requireUserVerification;
    private List<Map.Entry<PublicKeyCredentialType, COSEAlgorithmIdentifier>> credTypesAndPublicKeyAlgs;
    private List<PublicKeyCredentialDescriptor> excludeCredentialDescriptorList;
    private HashMap<ExtensionIdentifier, Extension> extensions;

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

    public boolean isRequireResidentKey() {
        return requireResidentKey;
    }

    public void setRequireResidentKey(boolean requireResidentKey) {
        this.requireResidentKey = requireResidentKey;
    }

    public boolean isRequireUserVerification() {
        return requireUserVerification;
    }

    public void setRequireUserVerification(boolean requireUserVerification) {
        this.requireUserVerification = requireUserVerification;
    }

    public List<Map.Entry<PublicKeyCredentialType, COSEAlgorithmIdentifier>> getCredTypesAndPublicKeyAlgs() {
        return credTypesAndPublicKeyAlgs;
    }

    public void setCredTypesAndPublicKeyAlgs(List<Map.Entry<PublicKeyCredentialType, COSEAlgorithmIdentifier>> credTypesAndPublicKeyAlgs) {
        this.credTypesAndPublicKeyAlgs = credTypesAndPublicKeyAlgs;
    }

    public List<PublicKeyCredentialDescriptor> getExcludeCredentialDescriptorList() {
        return excludeCredentialDescriptorList;
    }

    public void setExcludeCredentialDescriptorList(List<PublicKeyCredentialDescriptor> excludeCredentialDescriptorList) {
        this.excludeCredentialDescriptorList = excludeCredentialDescriptorList;
    }

    public HashMap<ExtensionIdentifier, Extension> getExtensions() {
        return extensions;
    }

    public void setExtensions(HashMap<ExtensionIdentifier, Extension> extensions) {
        this.extensions = extensions;
    }
}
