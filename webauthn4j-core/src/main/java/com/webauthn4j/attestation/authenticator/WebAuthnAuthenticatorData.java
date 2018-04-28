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

import com.webauthn4j.attestation.authenticator.extension.Extension;

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;

public class WebAuthnAuthenticatorData implements Serializable {
    public static final byte BIT_UP = (byte) 0b00000001;
    public static final byte BIT_UV = (byte) 0b00000100;
    public static final byte BIT_AT = (byte) 0b01000000;
    public static final byte BIT_ED = (byte) 0b10000000;

    private byte[] rpIdHash;
    private byte flags;
    private long counter;
    private WebAuthnAttestedCredentialData attestedCredentialData;
    private List<Extension> extensions;

    public byte[] getRpIdHash() {
        return rpIdHash;
    }

    public void setRpIdHash(byte[] rpIdHash) {
        if (rpIdHash.length != 32) {
            throw new IllegalArgumentException("rpIdHash must be 32 bytes length");
        }
        this.rpIdHash = rpIdHash;
    }

    public byte getFlags() {
        return flags;
    }

    public void setFlags(byte flags) {
        this.flags = flags;
    }

    public boolean isFlagUP() {
        return (this.flags & BIT_UP) != 0;
    }

    public void setFlagUP(boolean flagUP) {
        if (flagUP) {
            this.flags |= BIT_UP;
        } else {
            this.flags &= ~BIT_UP;
        }
    }

    public boolean isFlagUV() {
        return (this.flags & BIT_UV) != 0;
    }

    public void setFlagUV(boolean flagUV) {
        if (flagUV) {
            this.flags |= BIT_UV;
        } else {
            this.flags &= ~BIT_UV;
        }
    }

    public boolean isFlagAT() {
        return (this.flags & BIT_AT) != 0;
    }

    public void setFlagAT(boolean flagAT) {
        if (flagAT) {
            this.flags |= BIT_AT;
        } else {
            this.flags &= ~BIT_AT;
        }
    }

    public boolean isFlagED() {
        return (this.flags & BIT_ED) != 0;
    }

    public void setFlagED(boolean flagED) {
        if (flagED) {
            this.flags |= BIT_ED;
        } else {
            this.flags &= ~BIT_ED;
        }
    }

    public long getCounter() {
        return counter;
    }

    public void setCounter(long counter) {
        this.counter = counter;
    }

    public WebAuthnAttestedCredentialData getAttestedCredentialData() {
        return attestedCredentialData;
    }

    public void setAttestedCredentialData(WebAuthnAttestedCredentialData attestedCredentialData) {
        this.attestedCredentialData = attestedCredentialData;
    }

    public List<Extension> getExtensions() {
        return extensions;
    }

    public void setExtensions(List<Extension> extensions) {
        this.extensions = extensions;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof WebAuthnAuthenticatorData)) return false;

        WebAuthnAuthenticatorData that = (WebAuthnAuthenticatorData) o;

        if (flags != that.flags) return false;
        if (counter != that.counter) return false;
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
        result = 31 * result + (int) (counter ^ (counter >>> 32));
        result = 31 * result + (attestedCredentialData != null ? attestedCredentialData.hashCode() : 0);
        result = 31 * result + (extensions != null ? extensions.hashCode() : 0);
        return result;
    }
}
