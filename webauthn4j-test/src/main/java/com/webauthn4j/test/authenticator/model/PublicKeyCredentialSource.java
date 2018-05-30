package com.webauthn4j.test.authenticator.model;

import com.webauthn4j.test.client.PublicKeyCredentialType;

import java.security.PrivateKey;

public class PublicKeyCredentialSource {

    private PublicKeyCredentialType type;
    private byte[] id;
    private PrivateKey privateKey;
    private String rpId;
    private byte[] userHandle;
    private Object otherUI;

    public PublicKeyCredentialType getType() {
        return type;
    }

    public void setType(PublicKeyCredentialType type) {
        this.type = type;
    }

    public byte[] getId() {
        return id;
    }

    public void setId(byte[] id) {
        this.id = id;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public String getRpId() {
        return rpId;
    }

    public void setRpId(String rpId) {
        this.rpId = rpId;
    }

    public byte[] getUserHandle() {
        return userHandle;
    }

    public void setUserHandle(byte[] userHandle) {
        this.userHandle = userHandle;
    }

    public Object getOtherUI() {
        return otherUI;
    }

    public void setOtherUI(Object otherUI) {
        this.otherUI = otherUI;
    }
}
