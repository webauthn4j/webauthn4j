/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.data.attestation.authenticator;

import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.ExtensionAuthenticatorOutput;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Arrays;
import java.util.Objects;

/**
 * The authenticator data structure encodes contextual bindings made by the authenticator.
 * These bindings are controlled by the authenticator itself, and derive their trust from the WebAuthn Relying Party's
 * assessment of the security properties of the authenticator. In one extreme case, the authenticator may be embedded
 * in the client, and its bindings may be no more trustworthy than the client data. At the other extreme,
 * the authenticator may be a discrete entity with high-security hardware and software, connected to the client over
 * a secure channel. In both cases, the Relying Party receives the authenticator data in the same format, and uses
 * its knowledge of the authenticator to make trust decisions.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#sec-authenticator-data">§6.1 Authenticator Data.</a>
 */
public class AuthenticatorData<T extends ExtensionAuthenticatorOutput> {
    public static final byte BIT_UP = (byte) 0b00000001;
    public static final byte BIT_UV = (byte) 0b00000100;
    public static final byte BIT_BE = (byte) 0b00001000;
    public static final byte BIT_BS = (byte) 0b00010000;
    public static final byte BIT_AT = (byte) 0b01000000;
    public static final byte BIT_ED = (byte) 0b10000000;

    private final byte[] rpIdHash;
    private final byte flags;
    private final long signCount;
    private final AttestedCredentialData attestedCredentialData;
    private final AuthenticationExtensionsAuthenticatorOutputs<T> extensions;

    public AuthenticatorData(@NonNull byte[] rpIdHash, byte flags, long counter,
                             @Nullable AttestedCredentialData attestedCredentialData,
                             @Nullable AuthenticationExtensionsAuthenticatorOutputs<T> extensions) {
        assertRpIdHash(rpIdHash);
        this.rpIdHash = rpIdHash;
        this.flags = flags;
        this.signCount = counter;
        this.attestedCredentialData = attestedCredentialData;
        this.extensions = extensions;
    }

    public AuthenticatorData(@NonNull byte[] rpIdHash, byte flags, long counter,
                             @Nullable AttestedCredentialData attestedCredentialData) {
        assertRpIdHash(rpIdHash);
        this.rpIdHash = rpIdHash;
        this.flags = flags;
        this.signCount = counter;
        this.attestedCredentialData = attestedCredentialData;
        this.extensions = new AuthenticationExtensionsAuthenticatorOutputs<>();
    }

    public AuthenticatorData(@NonNull byte[] rpIdHash, byte flags, long counter,
                             @Nullable AuthenticationExtensionsAuthenticatorOutputs<T> extensions) {
        assertRpIdHash(rpIdHash);
        this.rpIdHash = rpIdHash;
        this.flags = flags;
        this.signCount = counter;
        this.attestedCredentialData = null;
        this.extensions = extensions;
    }

    public AuthenticatorData(@NonNull byte[] rpIdHash, byte flags, long counter) {
        assertRpIdHash(rpIdHash);
        this.rpIdHash = rpIdHash;
        this.flags = flags;
        this.signCount = counter;
        this.attestedCredentialData = null;
        this.extensions = new AuthenticationExtensionsAuthenticatorOutputs<>();
    }

    @SuppressWarnings("WeakerAccess")
    public static boolean checkFlagUP(byte flags) {
        return (flags & BIT_UP) != 0;
    }

    @SuppressWarnings("WeakerAccess")
    public static boolean checkFlagUV(byte flags) {
        return (flags & BIT_UV) != 0;
    }

    public static boolean checkFlagBE(byte flags) {
        return (flags & BIT_BE) != 0;
    }

    public static boolean checkFlagBS(byte flags) {
        return (flags & BIT_BS) != 0;
    }

    public static boolean checkFlagAT(byte flags) {
        return (flags & BIT_AT) != 0;
    }

    public static boolean checkFlagED(byte flags) {
        return (flags & BIT_ED) != 0;
    }

    public @NonNull byte[] getRpIdHash() {
        return ArrayUtil.clone(rpIdHash);
    }

    public byte getFlags() {
        return flags;
    }

    public boolean isFlagUP() {
        return checkFlagUP(this.flags);
    }

    public boolean isFlagUV() {
        return checkFlagUV(this.flags);
    }

    public boolean isFlagBE() {
        return checkFlagBE(this.flags);
    }

    public boolean isFlagBS() {
        return checkFlagBS(this.flags);
    }

    public boolean isFlagAT() {
        return checkFlagAT(this.flags);
    }

    public boolean isFlagED() {
        return checkFlagED(this.flags);
    }

    public long getSignCount() {
        return signCount;
    }

    public @Nullable AttestedCredentialData getAttestedCredentialData() {
        return attestedCredentialData;
    }

    public @Nullable AuthenticationExtensionsAuthenticatorOutputs<T> getExtensions() {
        return extensions;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticatorData<?> that = (AuthenticatorData<?>) o;
        return flags == that.flags &&
                signCount == that.signCount &&
                Arrays.equals(rpIdHash, that.rpIdHash) &&
                Objects.equals(attestedCredentialData, that.attestedCredentialData) &&
                Objects.equals(extensions, that.extensions);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(flags, signCount, attestedCredentialData, extensions);
        result = 31 * result + Arrays.hashCode(rpIdHash);
        return result;
    }

    @Override
    public String toString() {
        return "AuthenticatorData(" +
                "rpIdHash=" + ArrayUtil.toHexString(rpIdHash) +
                ", flags=" + String.format("%02X", flags) +
                ", signCount=" + signCount +
                ", attestedCredentialData=" + attestedCredentialData +
                ", extensions=" + extensions +
                ')';
    }

    private void assertRpIdHash(@Nullable @NonNull byte[] rpIdHash) {
        AssertUtil.notNull(rpIdHash, "rpIdHash must not be null");
    }
}
