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

package com.webauthn4j.data.attestation.authenticator;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.COSEKeyOperation;
import com.webauthn4j.data.attestation.statement.COSEKeyType;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.RSAUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.List;

public class RSACredentialPublicKey extends AbstractCredentialPublicKey {

    @JsonProperty("-1")
    private byte[] n;
    @JsonProperty("-2")
    private byte[] e;

    @SuppressWarnings("squid:S00107")
    @JsonCreator
    public RSACredentialPublicKey(
            @JsonProperty("2") byte[] keyId,
            @JsonProperty("3") COSEAlgorithmIdentifier algorithm,
            @JsonProperty("4") List<COSEKeyOperation> keyOpts,
            @JsonProperty("5") byte[] baseIV,
            @JsonProperty("-1") byte[] n,
            @JsonProperty("-2") byte[] e) {
        super(keyId, algorithm, keyOpts, baseIV);
        this.n = n;
        this.e = e;
    }

    public static RSACredentialPublicKey create(RSAPublicKey publicKey) {
        publicKey.getPublicExponent();
        byte[] n = publicKey.getModulus().toByteArray();
        byte[] e = publicKey.getPublicExponent().toByteArray();
        return new RSACredentialPublicKey(null, COSEAlgorithmIdentifier.RS256, null, null, n, e);
    }

    @Override
    public COSEKeyType getKeyType() {
        return COSEKeyType.RSA;
    }

    public byte[] getN() {
        return ArrayUtil.clone(n);
    }

    public byte[] getE() {
        return ArrayUtil.clone(e);
    }

    @Override
    public PublicKey getPublicKey() {
        RSAPublicKeySpec spec = new RSAPublicKeySpec(
                new BigInteger(1, getN()),
                new BigInteger(1, getE())
        );
        return RSAUtil.createPublicKey(spec);
    }

    @Override
    public void validate() {
        if (getAlgorithm() == null) {
            throw new ConstraintViolationException("algorithm must not be null");
        }
        if (e == null) {
            throw new ConstraintViolationException("e must not be null");
        }
        if (n == null) {
            throw new ConstraintViolationException("n must not be null");
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RSACredentialPublicKey that = (RSACredentialPublicKey) o;
        return Arrays.equals(n, that.n) &&
                Arrays.equals(e, that.e);
    }

    @Override
    public int hashCode() {

        int result = Arrays.hashCode(n);
        result = 31 * result + Arrays.hashCode(e);
        return result;
    }
}
