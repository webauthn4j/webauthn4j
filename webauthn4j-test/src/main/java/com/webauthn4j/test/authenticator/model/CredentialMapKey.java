package com.webauthn4j.test.authenticator.model;

import java.util.Arrays;
import java.util.Objects;

public class CredentialMapKey {

    private String rpId;
    private byte[] userHandle;

    public CredentialMapKey(String rpId, byte[] userHandle) {
        this.rpId = rpId;
        this.userHandle = userHandle;
    }

    public String getRpId() {
        return rpId;
    }

    public byte[] getUserHandle() {
        return userHandle;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CredentialMapKey that = (CredentialMapKey) o;
        return Objects.equals(rpId, that.rpId) &&
                Arrays.equals(userHandle, that.userHandle);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(rpId);
        result = 31 * result + Arrays.hashCode(userHandle);
        return result;
    }
}
