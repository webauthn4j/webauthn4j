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

import com.fasterxml.jackson.annotation.JsonProperty;

import java.security.Signature;


public abstract class AbstractCredentialPublicKey implements CredentialPublicKey {

    @JsonProperty("1")
    private int keyType;
    @JsonProperty("2")
    private byte[] keyId;
    @JsonProperty("3")
    private int algorithm;
    @JsonProperty("4")
    private int[] keyOpts;
    @JsonProperty("5")
    private byte[] baseIV;

    public int getKeyType() {
        return keyType;
    }

    public void setKeyType(int keyType) {
        this.keyType = keyType;
    }

    public byte[] getKeyId() {
        return keyId;
    }

    public void setKeyId(byte[] keyId) {
        this.keyId = keyId;
    }

    public int getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(int algorithm) {
        this.algorithm = algorithm;
    }

    public int[] getKeyOpts() {
        return keyOpts;
    }

    public void setKeyOpts(int[] keyOpts) {
        this.keyOpts = keyOpts;
    }

    public byte[] getBaseIV() {
        return baseIV;
    }

    public void setBaseIV(byte[] baseIV) {
        this.baseIV = baseIV;
    }

    @Override
    public boolean verifySignature(byte[] signature, byte[] data) {
        try {
            //公開鍵に基づくverifier
            Signature verifier = Signature.getInstance(getAlgorithmName());
            verifier.initVerify(getPublicKey());
            //検証
            verifier.update(data);

            return verifier.verify(signature);
        } catch (@SuppressWarnings("squid:S1166") Exception e) {
            return false;
        }
    }

    protected abstract String getAlgorithmName();
}
