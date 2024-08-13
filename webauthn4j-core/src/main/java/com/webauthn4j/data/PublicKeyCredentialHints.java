package com.webauthn4j.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;

import java.util.Objects;

public class PublicKeyCredentialHints {

    public static final PublicKeyCredentialHints SECURITY_KEY = new PublicKeyCredentialHints("security-key");

    public static final PublicKeyCredentialHints CLIENT_DEVICE = new PublicKeyCredentialHints("client-device");

    public static final PublicKeyCredentialHints HYBRID = new PublicKeyCredentialHints("hybrid");

    private final String value;

    private PublicKeyCredentialHints(String value) {
        this.value = value;
    }

    @JsonCreator
    public static @NotNull PublicKeyCredentialHints create(@NotNull String value) {
        AssertUtil.notNull(value, "value must not be null.");
        switch (value) {
            case "security-key":
                return SECURITY_KEY;
            case "client-device":
                return CLIENT_DEVICE;
            case "hybrid":
                return HYBRID;
            default:
                return new PublicKeyCredentialHints(value);
        }
    }

    @JsonValue
    public @NotNull String getValue() {
        return value;
    }

    @Override
    public String toString() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PublicKeyCredentialHints that = (PublicKeyCredentialHints) o;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

}
