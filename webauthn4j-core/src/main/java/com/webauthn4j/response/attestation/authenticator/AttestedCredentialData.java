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

package com.webauthn4j.response.attestation.authenticator;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

public class AttestedCredentialData implements Serializable {

    //~ Instance fields ================================================================================================
    private final AAGUID aaguid;

    private final byte[] credentialId;

    private final CredentialPublicKey credentialPublicKey;

    public AttestedCredentialData(AAGUID aaguid, byte[] credentialId, CredentialPublicKey credentialPublicKey) {
        this.aaguid = aaguid;
        this.credentialId = credentialId;
        this.credentialPublicKey = credentialPublicKey;
    }

    public AttestedCredentialData() {
        this.aaguid = null;
        this.credentialId = null;
        this.credentialPublicKey = null;
    }

    public AAGUID getAaguid() {
        return aaguid;
    }

    public byte[] getCredentialId() {
        return credentialId;
    }

    public CredentialPublicKey getCredentialPublicKey() {
        return credentialPublicKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AttestedCredentialData that = (AttestedCredentialData) o;
        return Objects.equals(aaguid, that.aaguid) &&
                Arrays.equals(credentialId, that.credentialId) &&
                Objects.equals(credentialPublicKey, that.credentialPublicKey);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(aaguid, credentialPublicKey);
        result = 31 * result + Arrays.hashCode(credentialId);
        return result;
    }
}
