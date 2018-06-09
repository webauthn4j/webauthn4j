/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.attestation.authenticator;

import com.webauthn4j.extension.authneticator.AuthenticatorExtensionOutput;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

public class AuthenticatorData {
    public static final byte BIT_UP = (byte) 0b00000001;
    public static final byte BIT_UV = (byte) 0b00000100;
    public static final byte BIT_AT = (byte) 0b01000000;
    public static final byte BIT_ED = (byte) 0b10000000;

    private final byte[] rpIdHash;
    private final byte flags;
    private final long signCount;
    private final AttestedCredentialData attestedCredentialData;
    private final Map<String, AuthenticatorExtensionOutput> extensions;

    public AuthenticatorData(byte[] rpIdHash, byte flags, long counter,
                             AttestedCredentialData attestedCredentialData,
                             Map<String, AuthenticatorExtensionOutput> extensions) {
        this.rpIdHash = rpIdHash;
        this.flags = flags;
        this.signCount = counter;
        this.attestedCredentialData = attestedCredentialData;
        this.extensions = extensions;
    }

    public AuthenticatorData(byte[] rpIdHash, byte flags, long counter,
                             AttestedCredentialData attestedCredentialData) {
        this.rpIdHash = rpIdHash;
        this.flags = flags;
        this.signCount = counter;
        this.attestedCredentialData = attestedCredentialData;
        this.extensions = Collections.emptyMap();
    }

    public AuthenticatorData(byte[] rpIdHash, byte flags, long counter,
                             Map<String, AuthenticatorExtensionOutput> extensions) {
        this.rpIdHash = rpIdHash;
        this.flags = flags;
        this.signCount = counter;
        this.attestedCredentialData = null;
        this.extensions = extensions;
    }

    public AuthenticatorData(byte[] rpIdHash, byte flags, long counter) {
        this.rpIdHash = rpIdHash;
        this.flags = flags;
        this.signCount = counter;
        this.attestedCredentialData = null;
        this.extensions = Collections.emptyMap();
    }

    @SuppressWarnings("WeakerAccess")
    public static boolean checkFlagUP(byte flags) {
        return (flags & BIT_UP) != 0;
    }

    @SuppressWarnings("WeakerAccess")
    public static boolean checkFlagUV(byte flags) {
        return (flags & BIT_UV) != 0;
    }

    public static boolean checkFlagAT(byte flags) {
        return (flags & BIT_AT) != 0;
    }

    public static boolean checkFlagED(byte flags) {
        return (flags & BIT_ED) != 0;
    }

    public byte[] getRpIdHash() {
        return rpIdHash;
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

    public boolean isFlagAT() {
        return checkFlagAT(this.flags);
    }

    public boolean isFlagED() {
        return checkFlagED(this.flags);
    }

    public long getSignCount() {
        return signCount;
    }

    public AttestedCredentialData getAttestedCredentialData() {
        return attestedCredentialData;
    }

    public Map<String, AuthenticatorExtensionOutput> getExtensions() {
        return extensions;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AuthenticatorData)) return false;

        AuthenticatorData that = (AuthenticatorData) o;

        if (flags != that.flags) return false;
        if (signCount != that.signCount) return false;
        if (!Arrays.equals(rpIdHash, that.rpIdHash)) return false;
        if (attestedCredentialData != null ? !attestedCredentialData.equals(that.attestedCredentialData) : that.attestedCredentialData != null)
            return false;
        return extensions != null ? extensions.equals(that.extensions) : that.extensions == null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        int result = Arrays.hashCode(rpIdHash);
        result = 31 * result + (int) flags;
        result = 31 * result + (int) (signCount ^ (signCount >>> 32));
        result = 31 * result + (attestedCredentialData != null ? attestedCredentialData.hashCode() : 0);
        result = 31 * result + (extensions != null ? extensions.hashCode() : 0);
        return result;
    }

}
