package com.webauthn4j.test.authenticator.model;

import com.webauthn4j.extension.ExtensionIdentifier;
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
    private Map<ExtensionIdentifier, AuthenticatorExtensionOutput> extensions;

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

    public Map<ExtensionIdentifier, AuthenticatorExtensionOutput> getExtensions() {
        return extensions;
    }

    public void setExtensions(Map<ExtensionIdentifier, AuthenticatorExtensionOutput> extensions) {
        this.extensions = extensions;
    }
}
