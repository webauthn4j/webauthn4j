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

package com.webauthn4j;

import com.webauthn4j.rp.RelyingParty;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;


/**
 * WebAuthnAuthenticationContext
 */
public class WebAuthnAuthenticationContext {

    //~ Instance fields ================================================================================================

    // user inputs
    private final byte[] credentialId;
    private final byte[] collectedClientData;
    private final byte[] authenticatorData;
    private final byte[] signature;

    // server property
    private final RelyingParty relyingParty;

    public WebAuthnAuthenticationContext(byte[] credentialId,
                                         byte[] collectedClientData,
                                         byte[] authenticatorData,
                                         byte[] signature,
                                         RelyingParty relyingParty) {
        this.credentialId = credentialId;
        this.collectedClientData = collectedClientData;
        this.authenticatorData = authenticatorData;
        this.signature = signature;
        this.relyingParty = relyingParty;
    }

    public byte[] getCredentialId() {
        return credentialId;
    }

    public byte[] getCollectedClientData() {
        return collectedClientData;
    }

    public String getCollectedClientDataJson() {
        return new String(collectedClientData, StandardCharsets.UTF_8);
    }

    public byte[] getAuthenticatorData() {
        return authenticatorData;
    }

    public byte[] getSignature() {
        return signature;
    }

    public RelyingParty getRelyingParty() {
        return relyingParty;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WebAuthnAuthenticationContext that = (WebAuthnAuthenticationContext) o;
        return Arrays.equals(credentialId, that.credentialId) &&
                Arrays.equals(collectedClientData, that.collectedClientData) &&
                Arrays.equals(authenticatorData, that.authenticatorData) &&
                Arrays.equals(signature, that.signature) &&
                Objects.equals(relyingParty, that.relyingParty);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(relyingParty);
        result = 31 * result + Arrays.hashCode(credentialId);
        result = 31 * result + Arrays.hashCode(collectedClientData);
        result = 31 * result + Arrays.hashCode(authenticatorData);
        result = 31 * result + Arrays.hashCode(signature);
        return result;
    }
}
