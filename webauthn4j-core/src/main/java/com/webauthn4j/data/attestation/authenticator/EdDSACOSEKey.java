package com.webauthn4j.data.attestation.authenticator;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.COSEKeyOperation;
import com.webauthn4j.data.attestation.statement.COSEKeyType;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.exception.UnexpectedCheckedException;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

@SuppressWarnings("Since15")
public class EdDSACOSEKey extends AbstractCOSEKey {

    private static final String CURVE_NULL_CHECK_MESSAGE = "curve must not be null";
    private static final String ALG_VALUE_CHECK_MESSAGE = "alg must be EdDSA";

    @JsonProperty("-1")
    private final Curve curve;

    @JsonProperty("-2")
    private byte[] x;

    @JsonProperty("-4")
    private byte[] d;

    /**
     * Constructor for key pair
     *
     * @param keyId     keyId
     * @param algorithm algorithm
     * @param keyOps    keyOps
     * @param curve     curve
     * @param x         x
     * @param d         d
     */
    @JsonCreator
    public EdDSACOSEKey(
            @Nullable @JsonProperty("2") byte[] keyId,
            @Nullable @JsonProperty("3") COSEAlgorithmIdentifier algorithm,
            @Nullable @JsonProperty("4") List<COSEKeyOperation> keyOps,
            @Nullable @JsonProperty("-1") Curve curve,
            @Nullable @JsonProperty("-2") byte[] x,
            @Nullable @JsonProperty("-4") byte[] d) {
        super(keyId, algorithm, keyOps, null);
        this.curve = curve;
        this.x = x;
        this.d = d;
    }

    /**
     * Create {@link EdDSACOSEKey} from {@link EdECPrivateKey}.
     *
     * @param privateKey private key
     * @param alg COSE algorithm identifier
     * @return {@link EdDSACOSEKey}
     */
    public static @NonNull EdDSACOSEKey create(@NonNull EdECPrivateKey privateKey, @Nullable COSEAlgorithmIdentifier alg) {
        AssertUtil.isTrue(alg == COSEAlgorithmIdentifier.EdDSA, ALG_VALUE_CHECK_MESSAGE);
        byte[] d = privateKey.getBytes().orElseThrow(()-> new IllegalArgumentException("privateKey must not be null"));
        Curve curve = getCurve(privateKey.getParams());

        return new EdDSACOSEKey(
                null,
                alg,
                null,
                curve,
                null,
                d
        );
    }

    /**
     * Create {@link EdDSACOSEKey} from {@link EdECPublicKey}.
     *
     * @param publicKey public key
     * @param alg COSE algorithm identifier
     * @return {@link EdDSACOSEKey}
     */
    public static @NonNull EdDSACOSEKey create(@NonNull EdECPublicKey publicKey, @Nullable COSEAlgorithmIdentifier alg) {
        AssertUtil.isTrue(alg == COSEAlgorithmIdentifier.EdDSA, ALG_VALUE_CHECK_MESSAGE);
        Curve curve = getCurve(publicKey.getParams());
        byte[] x = calcCOSEXParam(publicKey);
        return new EdDSACOSEKey(
                null,
                alg,
                null,
                curve,
                x,
                null
        );
    }

    /**
     * Create {@link EdDSACOSEKey} from {@link java.security.KeyPair}.
     *
     * @param keyPair key pair
     * @return {@link EdDSACOSEKey}
     */
    public static @NonNull EdDSACOSEKey create(@NonNull KeyPair keyPair, @Nullable COSEAlgorithmIdentifier alg) {
        AssertUtil.isTrue(alg == COSEAlgorithmIdentifier.EdDSA, ALG_VALUE_CHECK_MESSAGE);
        EdECPublicKey edECPublicKey = (EdECPublicKey)keyPair.getPublic();
        EdECPrivateKey edECPrivateKey = (EdECPrivateKey) keyPair.getPrivate();
        Curve curve = getCurve(edECPublicKey.getParams());
        byte[] x = calcCOSEXParam(edECPublicKey);
        byte[] d = edECPrivateKey.getBytes().orElseThrow(()-> new IllegalArgumentException("privateKey must not be null"));

        return new EdDSACOSEKey(
                null,
                alg,
                null,
                curve,
                x,
                d
        );
    }

    /**
     * Create {@link EdDSACOSEKey} from {@link EdECPrivateKey}.
     *
     * @param privateKey private key
     * @return {@link EdDSACOSEKey}
     */
    public static @NonNull EdDSACOSEKey create(@NonNull EdECPrivateKey privateKey){
        return create(privateKey, COSEAlgorithmIdentifier.EdDSA);
    }

    /**
     * Create {@link EdDSACOSEKey} from {@link EdECPublicKey}.
     *
     * @param publicKey public key
     * @return {@link EdDSACOSEKey}
     */
    public static @NonNull EdDSACOSEKey create(@NonNull EdECPublicKey publicKey) {
        return create(publicKey, COSEAlgorithmIdentifier.EdDSA);
    }

    /**
     * Create {@link EdDSACOSEKey} from {@link java.security.KeyPair}.
     *
     * @param keyPair key pair
     * @return {@link EdDSACOSEKey}
     */
    public static @NonNull EdDSACOSEKey create(@NonNull KeyPair keyPair) {
        return create(keyPair, COSEAlgorithmIdentifier.EdDSA);
    }

    @Override
    public boolean hasPublicKey() {
        return x != null;
    }

    @Override
    public boolean hasPrivateKey() {
        return d != null;
    }

    @Override
    public @Nullable PublicKey getPublicKey() {
        if (!hasPublicKey()) {
            return null;
        }

        try {
            KeyFactory factory = KeyFactory.getInstance("EdDSA");
            NamedParameterSpec namedParameterSpec = (NamedParameterSpec)curve.getParameterSpec();
            EdECPoint edECPoint = toEdECPoint(this.x);
            EdECPublicKeySpec keySpec = new EdECPublicKeySpec(namedParameterSpec, edECPoint);
            return factory.generatePublic(keySpec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    @Override
    public @Nullable PrivateKey getPrivateKey() {
        if (!hasPrivateKey()) {
            return null;
        }

        try {
            KeyFactory factory = KeyFactory.getInstance("EdDSA");
            NamedParameterSpec namedParameterSpec = (NamedParameterSpec)curve.getParameterSpec();
            EdECPrivateKeySpec keySpec = new EdECPrivateKeySpec(namedParameterSpec, this.d);
            return factory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new UnexpectedCheckedException(e);
        }
    }

    @Override
    public @NonNull COSEKeyType getKeyType() {
        return COSEKeyType.OKP;
    }

    public @Nullable Curve getCurve() {
        return curve;
    }

    public @Nullable byte[] getX() {
        return ArrayUtil.clone(x);
    }

    public @Nullable byte[] getD() {
        return ArrayUtil.clone(d);
    }

    @Override
    public void validate() {
        if (curve == null) {
            throw new ConstraintViolationException(CURVE_NULL_CHECK_MESSAGE);
        }
        if (curve != Curve.ED25519) {
            throw new ConstraintViolationException("curve must be Ed25519");
        }
        COSEAlgorithmIdentifier algorithm = getAlgorithm();
        if (algorithm != null && !Objects.equals(algorithm,COSEAlgorithmIdentifier.EdDSA)) {
            throw new ConstraintViolationException("algorithm must be EdDSA if present");
        }

        if (!hasPublicKey() && !hasPrivateKey()) {
            throw new ConstraintViolationException("x or d must be present");
        }
        if (x == null) {
            throw new ConstraintViolationException("x must not be null");
        }
    }

    static Curve getCurve(NamedParameterSpec namedParameterSpec){
        if(Objects.equals(namedParameterSpec.getName(), NamedParameterSpec.ED25519.getName())){
            return Curve.ED25519;
        }
        else {
            throw new IllegalArgumentException(String.format("%s is not supported. Ed25519 is the only supported curve.", namedParameterSpec.getName()));
        }
    }

    private static byte[] calcCOSEXParam(EdECPublicKey publicKey){
        Curve curve = getCurve(publicKey.getParams());
        BigInteger y = publicKey.getPoint().getY();
        byte[] bytes= ArrayUtil.convertToFixedByteArray(curve.getSize(), y);
        reverse(bytes);
        boolean xOdd = publicKey.getPoint().isXOdd();
        if(xOdd){
            bytes[bytes.length - 1] |= (byte) 0x80;
        }
        return bytes;
    }


    @SuppressWarnings("Since15")
    private static EdECPoint toEdECPoint(byte[] bytes)
    {
        byte[] cloned = bytes.clone();
        boolean xOdd = (cloned[bytes.length - 1] & 0x80) != 0;
        cloned[bytes.length - 1] &= (byte) 0x7F;
        reverse(cloned);
        BigInteger y = new BigInteger(1, cloned);
        return new EdECPoint(xOdd, y);
    }

    private static void reverse(byte [] bytes)
    {
        int i = 0;
        int j = bytes.length - 1;

        while(i < j)
        {
            byte tmp = bytes[i];
            bytes[i] = bytes[j];
            bytes[j] = tmp;
            i++;
            j--;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        EdDSACOSEKey that = (EdDSACOSEKey) o;
        return curve == that.curve && Arrays.equals(x, that.x) && Arrays.equals(d, that.d);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(super.hashCode(), curve);
        result = 31 * result + Arrays.hashCode(x);
        result = 31 * result + Arrays.hashCode(d);
        return result;
    }

    @Override
    public String toString() {
        return "EdDSACOSEKey(" +
                "keyId=" + ArrayUtil.toHexString(getKeyId()) +
                ", alg=" + getAlgorithm() +
                ", curve=" + curve +
                ", x=" + ArrayUtil.toHexString(x) +
                ", d=" + ArrayUtil.toHexString(d) +
                ')';
    }
}
