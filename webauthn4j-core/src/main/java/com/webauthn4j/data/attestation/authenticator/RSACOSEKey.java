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

public class RSACOSEKey extends AbstractCOSEKey {

    @JsonProperty("-1")
    private byte[] n;
    @JsonProperty("-2")
    private byte[] e;
    @JsonProperty("-3")
    private byte[] d;
    @JsonProperty("-4")
    private byte[] p;
    @JsonProperty("-5")
    private byte[] q;
    @JsonProperty("-6")
    private byte[] dP;
    @JsonProperty("-7")
    private byte[] dQ;
    @JsonProperty("-8")
    private byte[] qInv;

    /**
     * Constructor for key pair
     * @param keyId     keyId
     * @param algorithm algorithm
     * @param keyOps    keyOps
     * @param n         the RSA modulus n
     * @param e         the RSA public exponent e
     * @param d         the RSA private exponent d
     * @param p         the prime factor p of n
     * @param q         the prime factor q of n
     * @param dP        dP is d mod (p - 1)
     * @param dQ        dQ is d mod (q - 1)
     * @param qInv      qInv is the CRT coefficient q^(-1) mod p
     */
    @SuppressWarnings("squid:S00107")
    @JsonCreator
    public RSACOSEKey(
            @JsonProperty("2") byte[] keyId,
            @JsonProperty("3") COSEAlgorithmIdentifier algorithm,
            @JsonProperty("4") List<COSEKeyOperation> keyOps,
            @JsonProperty("-1") byte[] n,
            @JsonProperty("-2") byte[] e,
            @JsonProperty("-3") byte[] d,
            @JsonProperty("-4") byte[] p,
            @JsonProperty("-5") byte[] q,
            @JsonProperty("-6") byte[] dP,
            @JsonProperty("-7") byte[] dQ,
            @JsonProperty("-8") byte[] qInv
    ) {
        super(keyId, algorithm, keyOps, null);
        this.n = n;
        this.e = e;
        this.d = d;
        this.p = p;
        this.q = q;
        this.dP = dP;
        this.dQ = dQ;
        this.qInv = qInv;
    }

    /**
     * Constructor for public key
     * @param keyId     keyId
     * @param algorithm algorithm
     * @param keyOps    keyOps
     * @param n         n
     * @param e         e
     */
    @SuppressWarnings("squid:S00107")
    public RSACOSEKey(
            @JsonProperty("2") byte[] keyId,
            @JsonProperty("3") COSEAlgorithmIdentifier algorithm,
            @JsonProperty("4") List<COSEKeyOperation> keyOps,
            @JsonProperty("-1") byte[] n,
            @JsonProperty("-2") byte[] e) {
        super(keyId, algorithm, keyOps, null);
        this.n = n;
        this.e = e;
    }

    public static RSACOSEKey create(RSAPublicKey publicKey) {
        publicKey.getPublicExponent();
        byte[] n = publicKey.getModulus().toByteArray();
        byte[] e = publicKey.getPublicExponent().toByteArray();
        return new RSACOSEKey(null, COSEAlgorithmIdentifier.RS256, null, n, e);
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

    public byte[] getD() {
        return ArrayUtil.clone(d);
    }

    public byte[] getP() {
        return p;
    }

    public byte[] getQ() {
        return q;
    }

    public byte[] getDP() {
        return dP;
    }

    public byte[] getDQ() {
        return dQ;
    }

    public byte[] getQInv() {
        return qInv;
    }

    @Override
    public boolean hasPublicKey() {
        return n != null && e != null;
    }

    @Override
    public boolean hasPrivateKey() {
        return hasPublicKey() && d != null;
    }

    @Override
    public PublicKey getPublicKey() {

        if(!hasPublicKey()){
            return null;
        }

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
        if (n == null) {
            throw new ConstraintViolationException("n must not be null");
        }
        if (e == null) {
            throw new ConstraintViolationException("e must not be null");
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        RSACOSEKey that = (RSACOSEKey) o;
        return Arrays.equals(n, that.n) &&
                Arrays.equals(e, that.e) &&
                Arrays.equals(d, that.d) &&
                Arrays.equals(p, that.p) &&
                Arrays.equals(q, that.q) &&
                Arrays.equals(dP, that.dP) &&
                Arrays.equals(dQ, that.dQ) &&
                Arrays.equals(qInv, that.qInv);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + Arrays.hashCode(n);
        result = 31 * result + Arrays.hashCode(e);
        result = 31 * result + Arrays.hashCode(d);
        result = 31 * result + Arrays.hashCode(p);
        result = 31 * result + Arrays.hashCode(q);
        result = 31 * result + Arrays.hashCode(dP);
        result = 31 * result + Arrays.hashCode(dQ);
        result = 31 * result + Arrays.hashCode(qInv);
        return result;
    }
}
