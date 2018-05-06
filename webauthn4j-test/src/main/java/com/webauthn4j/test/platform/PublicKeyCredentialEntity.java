package com.webauthn4j.test.platform;

public class PublicKeyCredentialEntity {

    public PublicKeyCredentialEntity(String name, String icon) {
        this.name = name;
        this.icon = icon;
    }

    public PublicKeyCredentialEntity(String name) {
        this.name = name;
        this.icon = null;
    }

    public PublicKeyCredentialEntity(){}

    private String name;
    private String icon;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getIcon() {
        return icon;
    }

    public void setIcon(String icon) {
        this.icon = icon;
    }
}
