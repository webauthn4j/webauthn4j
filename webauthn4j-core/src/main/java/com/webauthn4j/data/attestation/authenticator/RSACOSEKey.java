/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
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
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.RSAUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.List;

public class RSACOSEKey extends AbstractCOSEKey {

    @JsonProperty("-1")
    private final byte[] n;
    @JsonProperty("-2")
    private final byte[] e;
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
     *
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
            @Nullable @JsonProperty("2") byte[] keyId,
            @Nullable @JsonProperty("3") COSEAlgorithmIdentifier algorithm,
            @Nullable @JsonProperty("4") List<COSEKeyOperation> keyOps,
            @Nullable @JsonProperty("-1") byte[] n,
            @Nullable @JsonProperty("-2") byte[] e,
            @Nullable @JsonProperty("-3") byte[] d,
            @Nullable @JsonProperty("-4") byte[] p,
            @Nullable @JsonProperty("-5") byte[] q,
            @Nullable @JsonProperty("-6") byte[] dP,
            @Nullable @JsonProperty("-7") byte[] dQ,
            @Nullable @JsonProperty("-8") byte[] qInv
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
     *
     * @param keyId     keyId
     * @param algorithm algorithm
     * @param keyOps    keyOps
     * @param n         n
     * @param e         e
     */
    @SuppressWarnings("squid:S00107")
    public RSACOSEKey(
            @Nullable @JsonProperty("2") byte[] keyId,
            @Nullable @JsonProperty("3") COSEAlgorithmIdentifier algorithm,
            @Nullable @JsonProperty("4") List<COSEKeyOperation> keyOps,
            @Nullable @JsonProperty("-1") byte[] n,
            @Nullable @JsonProperty("-2") byte[] e) {
        super(keyId, algorithm, keyOps, null);
        this.n = n;
        this.e = e;
    }

    public static @NonNull RSACOSEKey create(@NonNull RSAPrivateKey privateKey, @Nullable COSEAlgorithmIdentifier alg) {
        AssertUtil.notNull(privateKey, "privateKey must not be null");

        byte[] n = privateKey.getModulus().toByteArray();
        byte[] d = privateKey.getPrivateExponent().toByteArray();
        return new RSACOSEKey(null, alg, null, n, null, d, null, null, null, null, null);
    }


    public static @NonNull RSACOSEKey create(@NonNull RSAPublicKey publicKey, @Nullable COSEAlgorithmIdentifier alg) {
        AssertUtil.notNull(publicKey, "publicKey must not be null");

        publicKey.getPublicExponent();
        byte[] n = publicKey.getModulus().toByteArray();
        byte[] e = publicKey.getPublicExponent().toByteArray();
        return new RSACOSEKey(null, alg, null, n, e);
    }

    public static @NonNull RSACOSEKey create(@NonNull KeyPair keyPair, @Nullable COSEAlgorithmIdentifier alg) {
        AssertUtil.notNull(keyPair, "keyPair must not be null");

        if (keyPair.getPrivate() instanceof RSAPrivateKey && keyPair.getPublic() instanceof RSAPublicKey) {
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

            byte[] n = rsaPublicKey.getModulus().toByteArray();
            byte[] e = rsaPublicKey.getPublicExponent().toByteArray();
            byte[] d = rsaPrivateKey.getPrivateExponent().toByteArray();
            return new RSACOSEKey(null, alg, null, n, e, d, null, null, null, null, null);
        }
        else {
            throw new IllegalArgumentException();
        }
    }

    /**
     * Create {@link RSACOSEKey} from {@link RSAPrivateKey}.
     *
     * @param privateKey privateKey
     * @return {@link RSACOSEKey}
     */
    public static @NonNull RSACOSEKey create(@NonNull RSAPrivateKey privateKey) {
        return create(privateKey, null);
    }

    /**
     * Create {@link RSACOSEKey} from {@link RSAPublicKey}.
     *
     * @param publicKey publicKey
     * @return {@link RSACOSEKey}
     */
    public static @NonNull RSACOSEKey create(@NonNull RSAPublicKey publicKey) {
        return create(publicKey, null);
    }

    /**
     * Create {@link RSACOSEKey} from {@link KeyPair}.
     *
     * @param keyPair keyPair
     * @return {@link RSACOSEKey}
     */
    public static @NonNull RSACOSEKey create(@NonNull KeyPair keyPair) {
        return create(keyPair, null);
    }

    @Override
    public @NonNull COSEKeyType getKeyType() {
        return COSEKeyType.RSA;
    }

    public @Nullable byte[] getN() {
        return ArrayUtil.clone(n);
    }

    public @Nullable byte[] getE() {
        return ArrayUtil.clone(e);
    }

    public @Nullable byte[] getD() {
        return ArrayUtil.clone(d);
    }

    public @Nullable byte[] getP() {
        return ArrayUtil.clone(p);
    }

    public @Nullable byte[] getQ() {
        return ArrayUtil.clone(q);
    }

    public @Nullable byte[] getDP() {
        return ArrayUtil.clone(dP);
    }

    public @Nullable byte[] getDQ() {
        return ArrayUtil.clone(dQ);
    }

    public @Nullable byte[] getQInv() {
        return ArrayUtil.clone(qInv);
    }

    @Override
    public boolean hasPublicKey() {
        return n != null && e != null;
    }

    @Override
    public boolean hasPrivateKey() {
        return n != null && d != null;
    }

    @Override
    public @Nullable PublicKey getPublicKey() {
        if (!hasPublicKey()) {
            return null;
        }
        RSAPublicKeySpec spec = new RSAPublicKeySpec(
                new BigInteger(1, getN()),
                new BigInteger(1, getE())
        );
        return RSAUtil.createPublicKey(spec);
    }

    @Override
    public @Nullable PrivateKey getPrivateKey() {
        if (!hasPrivateKey()) {
            return null;
        }
        RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(
                new BigInteger(1, getN()),
                new BigInteger(1, getD())
        );
        return RSAUtil.createPrivateKey(rsaPrivateKeySpec);
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
    public boolean equals(@Nullable Object o) {
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

    @Override
    public String toString() {
        return "RSACOSEKey(" +
                "n=" + ArrayUtil.toHexString(n) +
                ", e=" + ArrayUtil.toHexString(e) +
                ", d=" + ArrayUtil.toHexString(d) +
                ", p=" + ArrayUtil.toHexString(p) +
                ", q=" + ArrayUtil.toHexString(q) +
                ", dP=" + ArrayUtil.toHexString(dP) +
                ", dQ=" + ArrayUtil.toHexString(dQ) +
                ", qInv=" + ArrayUtil.toHexString(qInv) +
                ')';
    }
}
