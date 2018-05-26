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
import com.webauthn4j.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.attestation.statement.COSEKeyOperation;
import com.webauthn4j.attestation.statement.COSEKeyType;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Objects;

public abstract class AbstractCredentialPublicKey implements CredentialPublicKey {

    @JsonProperty("1")
    private COSEKeyType keyType;

    @JsonProperty("2")
    private byte[] keyId;

    @JsonProperty("3")
    private COSEAlgorithmIdentifier algorithm;

    @JsonProperty("4")
    private COSEKeyOperation[] keyOpts;

    @JsonProperty("5")
    private byte[] baseIV;

    AbstractCredentialPublicKey(COSEKeyType keyType, byte[] keyId, COSEAlgorithmIdentifier algorithm, COSEKeyOperation[] keyOpts, byte[] baseIV) {
        this.keyType = keyType;
        this.keyId = keyId;
        this.algorithm = algorithm;
        this.keyOpts = keyOpts;
        this.baseIV = baseIV;
    }

    AbstractCredentialPublicKey() {
    }

    public COSEKeyType getKeyType() {
        return keyType;
    }

    public byte[] getKeyId() {
        return keyId;
    }

    public COSEAlgorithmIdentifier getAlgorithm() {
        return algorithm;
    }

    public COSEKeyOperation[] getKeyOpts() {
        return keyOpts;
    }

    public byte[] getBaseIV() {
        return baseIV;
    }

    @JsonIgnore
    private String getAlgorithmName() {
        return algorithm.getName();
    }

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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AbstractCredentialPublicKey that = (AbstractCredentialPublicKey) o;
        return keyType == that.keyType &&
                Arrays.equals(keyId, that.keyId) &&
                algorithm == that.algorithm &&
                Arrays.equals(keyOpts, that.keyOpts) &&
                Arrays.equals(baseIV, that.baseIV);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(keyType, algorithm);
        result = 31 * result + Arrays.hashCode(keyId);
        result = 31 * result + Arrays.hashCode(keyOpts);
        result = 31 * result + Arrays.hashCode(baseIV);
        return result;
    }
}
