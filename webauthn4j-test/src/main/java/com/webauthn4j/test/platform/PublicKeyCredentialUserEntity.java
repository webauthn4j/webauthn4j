package com.webauthn4j.test.platform;

public class PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity {
    private byte[] id;
    private String displayName;

    public PublicKeyCredentialUserEntity(byte[] id, String name, String displayName, String icon) {
        super(name, icon);
        this.id = id;
        this.displayName = displayName;
    }

    public PublicKeyCredentialUserEntity(byte[] id, String name, String displayName) {
        super(name);
        this.id = id;
        this.displayName = displayName;
    }

    public PublicKeyCredentialUserEntity() {
        super();
    }

    public byte[] getId() {
        return id;
    }

    public void setId(byte[] id) {
        this.id = id;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }
}
