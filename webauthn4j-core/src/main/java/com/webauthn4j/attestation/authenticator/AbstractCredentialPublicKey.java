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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

public abstract class AbstractCredentialPublicKey implements CredentialPublicKey {

    @JsonProperty("1")
    private int keyType;
    @JsonProperty("2")
    private byte[] keyId;
    @JsonProperty("4")
    private int[] keyOpts;
    @JsonProperty("5")
    private byte[] baseIV;

    public AbstractCredentialPublicKey(int keyType, byte[] keyId, int[] keyOpts, byte[] baseIV) {
        this.keyType = keyType;
        this.keyId = keyId;
        this.keyOpts = keyOpts;
        this.baseIV = baseIV;
    }

    public AbstractCredentialPublicKey(){}

    public int getKeyType() {
        return keyType;
    }

    public byte[] getKeyId() {
        return keyId;
    }

    public int[] getKeyOpts() {
        return keyOpts;
    }

    public byte[] getBaseIV() {
        return baseIV;
    }

    @JsonIgnore
    protected abstract String getAlgorithmName();

    @Override
    public boolean verifySignature(byte[] signature, byte[] data) {
        try {
            Signature verifier = Signature.getInstance(getAlgorithmName());
            verifier.initVerify(getPublicKey());
            verifier.update(data);

            return verifier.verify(signature);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | RuntimeException e) {
            return false;
        }
    }
}
