package com.webauthn4j.test.platform;

public class PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity {

    private String id;

    public PublicKeyCredentialRpEntity(String id, String name, String icon) {
        super(name, icon);
        this.id = id;
    }

    public PublicKeyCredentialRpEntity(String id, String name) {
        super(name);
        this.id = id;
    }

    public PublicKeyCredentialRpEntity(String name) {
        super(name);
        this.id = null;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }
}
