package com.webauthn4j.test.platform;

import com.webauthn4j.util.Base64UrlUtil;

public class PublicKeyCredential<T extends AuthenticatorResponse> {

    private String id;
    private byte[] rawId;
    private T authenticatorResponse;

    public PublicKeyCredential(byte[] credentialId, T authenticatorResponse) {
        this.id = Base64UrlUtil.encodeToString(credentialId);
        this.rawId = credentialId;
        this.authenticatorResponse = authenticatorResponse;
    }

    public String getType() {
        return "public-key";
    }

    public String getId() {
        return id;
    }

    public byte[] getRawId() {
        return rawId;
    }

    public T getAuthenticatorResponse() {
        return authenticatorResponse;
    }
}
