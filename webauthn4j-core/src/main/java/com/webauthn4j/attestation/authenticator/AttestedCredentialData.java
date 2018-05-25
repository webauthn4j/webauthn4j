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

import java.io.Serializable;
import java.util.Arrays;

public class AttestedCredentialData implements Serializable {

    //~ Instance fields ================================================================================================
    private final byte[] aaGuid;

    private final byte[] credentialId;

    private final CredentialPublicKey credentialPublicKey;

    public AttestedCredentialData(byte[] aaGuid, byte[] credentialId, CredentialPublicKey credentialPublicKey) {
        this.aaGuid = aaGuid;
        this.credentialId = credentialId;
        this.credentialPublicKey = credentialPublicKey;
    }

    public AttestedCredentialData() {
        this.aaGuid = null;
        this.credentialId = null;
        this.credentialPublicKey = null;
    }

    public byte[] getAaGuid() {
        return aaGuid;
    }

    public byte[] getCredentialId() {
        return credentialId;
    }

    public CredentialPublicKey getCredentialPublicKey() {
        return credentialPublicKey;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AttestedCredentialData)) return false;

        AttestedCredentialData that = (AttestedCredentialData) o;

        if (!Arrays.equals(aaGuid, that.aaGuid)) return false;
        if (!Arrays.equals(credentialId, that.credentialId)) return false;
        return credentialPublicKey != null ? credentialPublicKey.equals(that.credentialPublicKey) : that.credentialPublicKey == null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode() {
        int result = Arrays.hashCode(aaGuid);
        result = 31 * result + Arrays.hashCode(credentialId);
        result = 31 * result + (credentialPublicKey != null ? credentialPublicKey.hashCode() : 0);
        return result;
    }
}
