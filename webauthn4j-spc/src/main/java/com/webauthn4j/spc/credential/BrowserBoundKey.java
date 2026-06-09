package com.webauthn4j.spc.credential;

import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.util.AssertUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;

public class BrowserBoundKey {

    private final COSEKey publicKey;

    public BrowserBoundKey(@NotNull COSEKey publicKey) {
        AssertUtil.notNull(publicKey, "publicKey must not be null");
        this.publicKey = publicKey;
    }

    public @NotNull COSEKey getPublicKey() {
        return publicKey;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BrowserBoundKey that = (BrowserBoundKey) o;
        return Objects.equals(publicKey, that.publicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(publicKey);
    }

    @Override
    public String toString() {
        return "BrowserBoundKey(publicKey=" + publicKey + ')';
    }
}
