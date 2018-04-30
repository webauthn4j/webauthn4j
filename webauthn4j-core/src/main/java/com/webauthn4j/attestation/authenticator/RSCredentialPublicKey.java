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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.util.exception.UnexpectedCheckedException;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Objects;

public class RSCredentialPublicKey extends AbstractCredentialPublicKey {

    @JsonProperty("3")
    protected RSSignatureAlgorithm algorithm;
    @JsonProperty("-1")
    private byte[] n;
    @JsonProperty("-2")
    private byte[] e;

    public RSCredentialPublicKey(int keyType, byte[] keyId, int[] keyOpts, byte[] baseIV, RSSignatureAlgorithm algorithm, byte[] n, byte[] e) {
        super(keyType, keyId, keyOpts, baseIV);
        this.algorithm = algorithm;
        this.n = n;
        this.e = e;
    }

    public RSCredentialPublicKey(){super();}

    public byte[] getN() {
        return n;
    }

    public byte[] getE() {
        return e;
    }

    public RSSignatureAlgorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    protected String getAlgorithmName() {
        return algorithm.getName();
    }

    @Override
    public PublicKey getPublicKey() {
        RSAPublicKeySpec spec = new RSAPublicKeySpec(
                new BigInteger(1, getN()),
                new BigInteger(1, getE())
        );
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePublic(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RSCredentialPublicKey that = (RSCredentialPublicKey) o;
        return Arrays.equals(n, that.n) &&
                Arrays.equals(e, that.e) &&
                Objects.equals(algorithm, that.algorithm);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(algorithm);
        result = 31 * result + Arrays.hashCode(n);
        result = 31 * result + Arrays.hashCode(e);
        return result;
    }
}
