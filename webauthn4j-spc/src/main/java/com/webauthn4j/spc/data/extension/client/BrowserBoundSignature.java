package com.webauthn4j.spc.data.extension.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Arrays;

public class BrowserBoundSignature {

    private final byte[] signature;

    @JsonCreator
    public BrowserBoundSignature(
            @NotNull @JsonProperty("signature") byte[] signature) {
        AssertUtil.notNull(signature, "signature must not be null");
        this.signature = ArrayUtil.clone(signature);
    }

    public @NotNull byte[] getSignature() {
        return ArrayUtil.clone(signature);
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        BrowserBoundSignature that = (BrowserBoundSignature) o;
        return Arrays.equals(signature, that.signature);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(signature);
    }

    @Override
    public String toString() {
        return "BrowserBoundSignature(" +
                "signature=" + ArrayUtil.toHexString(signature) +
                ')';
    }
}
