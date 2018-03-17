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

package net.sharplab.springframework.security.webauthn.attestation.authenticator;

import java.io.Serializable;
import java.util.Arrays;

public class WebAuthnAttestedCredentialData implements Serializable {

    //~ Instance fields ================================================================================================
    private byte[] aaGuid;
    private byte[] credentialId;
    private AbstractCredentialPublicKey credentialPublicKey;


    public byte[] getAaGuid() {
        return aaGuid;
    }

    public void setAaGuid(byte[] aaGuid) {
        this.aaGuid = aaGuid;
    }

    public byte[] getCredentialId() {
        return credentialId;
    }

    public void setCredentialId(byte[] credentialId) {
        this.credentialId = credentialId;
    }

    public AbstractCredentialPublicKey getCredentialPublicKey() {
        return credentialPublicKey;
    }

    public void setCredentialPublicKey(AbstractCredentialPublicKey credentialPublicKey) {
        this.credentialPublicKey = credentialPublicKey;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof WebAuthnAttestedCredentialData)) return false;

        WebAuthnAttestedCredentialData that = (WebAuthnAttestedCredentialData) o;

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
