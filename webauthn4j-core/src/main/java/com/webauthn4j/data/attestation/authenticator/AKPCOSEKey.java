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
import com.webauthn4j.data.internal.asn1.der.ASN1BitString;
import com.webauthn4j.data.internal.asn1.der.ASN1Integer;
import com.webauthn4j.data.internal.asn1.der.ASN1ObjectIdentifier;
import com.webauthn4j.data.internal.asn1.der.ASN1OctetString;
import com.webauthn4j.data.internal.asn1.der.ASN1Sequence;
import com.webauthn4j.data.attestation.authenticator.internal.MLDSASeedExpander;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.exception.UnexpectedCheckedException;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;

/**
 * COSE key implementation for the AKP (Algorithm Key Pair) key type.
 * AKP is used by post-quantum cryptographic algorithms such as ML-DSA, SLH-DSA, and FN-DSA.
 * <p>
 * ML-DSA algorithms require JDK 24 or later at runtime.
 *
 * @see <a href="https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/">Use of ML-DSA in COSE and JOSE</a>
 */
public class AKPCOSEKey extends AbstractCOSEKey {

    private static final int ML_DSA_SEED_LENGTH = 32;

    // Raw OID value bytes for ML-DSA algorithms defined in FIPS 204 (without tag and length)
    private static final byte[] ML_DSA_44_OID = {
            0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11
    };
    private static final byte[] ML_DSA_65_OID = {
            0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12
    };
    private static final byte[] ML_DSA_87_OID = {
            0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13
    };

    @JsonProperty("-1")
    private byte[] pub;

    @JsonProperty("-2")
    private byte[] priv;

    /**
     * Constructor for AKP key
     *
     * @param keyId     keyId
     * @param algorithm algorithm (required for AKP)
     * @param keyOps    keyOps
     * @param pub       raw public key bytes
     * @param priv      raw private key bytes (seed for ML-DSA)
     */
    @JsonCreator
    public AKPCOSEKey(
            @Nullable @JsonProperty("2") byte[] keyId,
            @Nullable @JsonProperty("3") COSEAlgorithmIdentifier algorithm,
            @Nullable @JsonProperty("4") List<COSEKeyOperation> keyOps,
            @Nullable @JsonProperty("-1") byte[] pub,
            @Nullable @JsonProperty("-2") byte[] priv) {
        super(keyId, algorithm, keyOps, null);
        this.pub = ArrayUtil.clone(pub);
        this.priv = ArrayUtil.clone(priv);
    }

    // No create(KeyPair, alg) method is provided because the JDK does not expose
    // the ML-DSA seed from a generated KeyPair. RFC 9964 Section 4 requires priv
    // to be the 32-byte seed, which cannot be extracted from JDK's PrivateKey.
    // Use the constructor directly with a seed obtained via Bouncy Castle.

    /**
     * Create {@link AKPCOSEKey} from a {@link PublicKey}.
     *
     * @param publicKey public key
     * @param alg       COSE algorithm identifier
     * @return {@link AKPCOSEKey}
     */
    public static @NotNull AKPCOSEKey create(@NotNull PublicKey publicKey, @NotNull COSEAlgorithmIdentifier alg) {
        AssertUtil.notNull(publicKey, "publicKey must not be null");
        AssertUtil.notNull(alg, "alg must not be null");
        byte[] rawPub = extractRawFromSubjectPublicKeyInfo(publicKey.getEncoded());
        return new AKPCOSEKey(null, alg, null, rawPub, null);
    }

    @Override
    public boolean hasPublicKey() {
        return pub != null;
    }

    @Override
    public boolean hasPrivateKey() {
        return priv != null;
    }

    @Override
    public @Nullable PublicKey getPublicKey() {
        if (!hasPublicKey()) {
            return null;
        }
        try {
            COSEAlgorithmIdentifier alg = getAlgorithm();
            if (alg == null) {
                throw new IllegalStateException("algorithm must not be null for AKP key type");
            }
            String jcaName = alg.toSignatureAlgorithm().getJcaName();
            KeyFactory kf = KeyFactory.getInstance(jcaName);
            byte[] encoded = buildSubjectPublicKeyInfo(pub, jcaName);
            return kf.generatePublic(new X509EncodedKeySpec(encoded));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    @Override
    public @Nullable PrivateKey getPrivateKey() {
        if (!hasPrivateKey()) {
            return null;
        }
        COSEAlgorithmIdentifier alg = getAlgorithm();
        if (alg == null) {
            throw new IllegalStateException("algorithm must not be null for AKP key type");
        }
        String jcaName = alg.toSignatureAlgorithm().getJcaName();
        return expandMLDSASeedToPrivateKey(priv, jcaName);
    }

    private static boolean isMLDSAAlgorithm(COSEAlgorithmIdentifier alg) {
        return COSEAlgorithmIdentifier.ML_DSA_44.equals(alg)
                || COSEAlgorithmIdentifier.ML_DSA_65.equals(alg)
                || COSEAlgorithmIdentifier.ML_DSA_87.equals(alg);
    }

    private static PrivateKey expandMLDSASeedToPrivateKey(byte[] seed, String jcaName) {
        try {
            byte[] expandedKey = MLDSASeedExpander.expand(seed, jcaName);
            KeyFactory kf = KeyFactory.getInstance(jcaName);
            byte[] pkcs8 = buildPKCS8PrivateKeyInfo(expandedKey, jcaName);
            return kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        } catch (NoClassDefFoundError e) {
            throw new UnsupportedOperationException(
                    "Bouncy Castle is required to expand ML-DSA seed to a private key. " +
                    "Add org.bouncycastle:bcprov-jdk18on to your classpath.", e);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    @Override
    public @NotNull COSEKeyType getKeyType() {
        return COSEKeyType.AKP;
    }

    public @Nullable byte[] getPub() {
        return ArrayUtil.clone(pub);
    }

    public @Nullable byte[] getPriv() {
        return ArrayUtil.clone(priv);
    }

    @Override
    public void validate() {
        COSEAlgorithmIdentifier algorithm = getAlgorithm();
        if (algorithm == null) {
            throw new ConstraintViolationException("algorithm must not be null for AKP key type");
        }
        if (!hasPublicKey() && !hasPrivateKey()) {
            throw new ConstraintViolationException("pub or priv must be present");
        }
        if (pub == null) {
            throw new ConstraintViolationException("pub must not be null");
        }
    }

    /**
     * Build X.509 SubjectPublicKeyInfo DER encoding from raw public key bytes.
     */
    static byte[] buildSubjectPublicKeyInfo(byte[] rawPublicKey, String jcaName) {
        return ASN1Sequence.create(
                ASN1Sequence.create(ASN1ObjectIdentifier.create(getOidForAlgorithm(jcaName))),
                ASN1BitString.create(rawPublicKey)
        ).toBytes();
    }

    /**
     * Build PKCS#8 PrivateKeyInfo DER encoding from raw private key bytes.
     */
    static byte[] buildPKCS8PrivateKeyInfo(byte[] rawPrivateKey, String jcaName) {
        return ASN1Sequence.create(
                ASN1Integer.create(new byte[]{0x00}),
                ASN1Sequence.create(ASN1ObjectIdentifier.create(getOidForAlgorithm(jcaName))),
                ASN1OctetString.create(ASN1OctetString.create(rawPrivateKey).toBytes())
        ).toBytes();
    }

    /**
     * Extract raw public key bytes from X.509 SubjectPublicKeyInfo DER encoding.
     */
    static byte[] extractRawFromSubjectPublicKeyInfo(byte[] encoded) {
        ASN1Sequence spki = ASN1Sequence.parse(encoded);
        return ((ASN1BitString) spki.get(1)).getContent();
    }

    /**
     * Extract raw private key bytes from PKCS#8 PrivateKeyInfo DER encoding.
     */
    static byte[] extractRawFromPKCS8(byte[] encoded) {
        ASN1Sequence pkcs8 = ASN1Sequence.parse(encoded);
        ASN1OctetString outerOctet = (ASN1OctetString) pkcs8.get(2);
        ASN1OctetString innerOctet = ASN1OctetString.parse(outerOctet.getValue());
        return innerOctet.getValue();
    }

    private static byte[] getOidForAlgorithm(String jcaName) {
        switch (jcaName) {
            case "ML-DSA-44":
                return ML_DSA_44_OID;
            case "ML-DSA-65":
                return ML_DSA_65_OID;
            case "ML-DSA-87":
                return ML_DSA_87_OID;
            default:
                throw new IllegalArgumentException("Unsupported AKP algorithm: " + jcaName);
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        AKPCOSEKey that = (AKPCOSEKey) o;
        return Arrays.equals(pub, that.pub) && Arrays.equals(priv, that.priv);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + Arrays.hashCode(pub);
        result = 31 * result + Arrays.hashCode(priv);
        return result;
    }

    @Override
    public String toString() {
        return "AKPCOSEKey(" +
                "keyId=" + ArrayUtil.toHexString(getKeyId()) +
                ", alg=" + getAlgorithm() +
                ", pub=" + (pub != null ? pub.length + " bytes" : "null") +
                ", priv=" + (priv != null ? priv.length + " bytes" : "null") +
                ')';
    }
}
