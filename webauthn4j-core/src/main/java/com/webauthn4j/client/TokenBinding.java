package com.webauthn4j.client;

import com.webauthn4j.util.Base64UrlUtil;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

public class TokenBinding implements Serializable {

    private TokenBindingStatus status;
    private String id;

    public TokenBinding(TokenBindingStatus status, String id) {
        this.status = status;
        this.id = id;
    }

    public TokenBinding(TokenBindingStatus status, byte[] id) {
        this.status = status;
        this.id = Base64UrlUtil.encodeToString(id);
    }

    public TokenBinding() {
    }

    public TokenBindingStatus getStatus() {
        return status;
    }

    public String getId() {
        return id;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        TokenBinding that = (TokenBinding) o;
        return status == that.status &&
                Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {

        return Objects.hash(status, id);
    }
}
