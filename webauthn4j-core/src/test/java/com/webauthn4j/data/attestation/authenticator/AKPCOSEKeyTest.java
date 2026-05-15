package com.webauthn4j.data.attestation.authenticator;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.SignatureAlgorithm;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.COSEKeyType;
import com.webauthn4j.util.SignatureUtil;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;

import java.security.*;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AKPCOSEKeyTest {

    private static final byte[] DUMMY_PUB = new byte[1952];  // ML-DSA-65 public key size
    private static final byte[] DUMMY_PRIV = new byte[32];   // ML-DSA seed size

    @Test
    void constructor_test() {
        // Given
        AKPCOSEKey key = new AKPCOSEKey(null, COSEAlgorithmIdentifier.ML_DSA_65, null, DUMMY_PUB, DUMMY_PRIV);

        // Then
        assertThat(key.getKeyType()).isEqualTo(COSEKeyType.AKP);
        assertThat(key.getAlgorithm()).isEqualTo(COSEAlgorithmIdentifier.ML_DSA_65);
        assertThat(key.getPub()).isEqualTo(DUMMY_PUB);
        assertThat(key.getPriv()).isEqualTo(DUMMY_PRIV);
        assertThat(key.hasPublicKey()).isTrue();
        assertThat(key.hasPrivateKey()).isTrue();
    }

    @Test
    void constructor_with_pub_only_test() {
        // Given
        AKPCOSEKey key = new AKPCOSEKey(null, COSEAlgorithmIdentifier.ML_DSA_65, null, DUMMY_PUB, null);

        // Then
        assertThat(key.hasPublicKey()).isTrue();
        assertThat(key.hasPrivateKey()).isFalse();
        assertThat(key.getPriv()).isNull();
    }

    @Test
    void getKeyType_test() {
        // Given
        AKPCOSEKey key = new AKPCOSEKey(null, COSEAlgorithmIdentifier.ML_DSA_44, null, DUMMY_PUB, null);

        // Then
        assertThat(key.getKeyType()).isEqualTo(COSEKeyType.AKP);
    }

    @Test
    void validate_test() {
        // Given
        AKPCOSEKey key = new AKPCOSEKey(null, COSEAlgorithmIdentifier.ML_DSA_65, null, DUMMY_PUB, DUMMY_PRIV);

        // When / Then
        assertThatCode(key::validate).doesNotThrowAnyException();
    }

    @Test
    void validate_with_null_algorithm_test() {
        // Given
        AKPCOSEKey key = new AKPCOSEKey(null, null, null, DUMMY_PUB, null);

        // When / Then
        assertThrows(ConstraintViolationException.class, key::validate);
    }

    @Test
    void validate_with_null_pub_and_null_priv_test() {
        // Given
        AKPCOSEKey key = new AKPCOSEKey(null, COSEAlgorithmIdentifier.ML_DSA_65, null, null, null);

        // When / Then
        assertThrows(ConstraintViolationException.class, key::validate);
    }

    @Test
    void validate_with_null_pub_test() {
        // Given
        AKPCOSEKey key = new AKPCOSEKey(null, COSEAlgorithmIdentifier.ML_DSA_65, null, null, DUMMY_PRIV);

        // When / Then
        assertThrows(ConstraintViolationException.class, key::validate);
    }

    @Test
    void equals_hashCode_test() {
        // Given
        AKPCOSEKey keyA = new AKPCOSEKey(null, COSEAlgorithmIdentifier.ML_DSA_65, null, DUMMY_PUB, DUMMY_PRIV);
        AKPCOSEKey keyB = new AKPCOSEKey(null, COSEAlgorithmIdentifier.ML_DSA_65, null, DUMMY_PUB, DUMMY_PRIV);

        // Then
        assertThat(keyA)
                .isEqualTo(keyB)
                .hasSameHashCodeAs(keyB);
    }

    @Test
    void equals_with_different_pub_test() {
        // Given
        byte[] differentPub = new byte[1952];
        differentPub[0] = 1;
        AKPCOSEKey keyA = new AKPCOSEKey(null, COSEAlgorithmIdentifier.ML_DSA_65, null, DUMMY_PUB, null);
        AKPCOSEKey keyB = new AKPCOSEKey(null, COSEAlgorithmIdentifier.ML_DSA_65, null, differentPub, null);

        // Then
        assertThat(keyA).isNotEqualTo(keyB);
    }

    @Test
    void toString_test() {
        // Given
        AKPCOSEKey key = new AKPCOSEKey(null, COSEAlgorithmIdentifier.ML_DSA_65, null, DUMMY_PUB, null);

        // Then
        assertThat(key.toString()).contains("AKPCOSEKey(");
        assertThat(key.toString()).contains("alg=ML-DSA-65");
        assertThat(key.toString()).contains("1952 bytes");
    }

    @Test
    void buildSubjectPublicKeyInfo_roundtrip_test() {
        // Given
        byte[] rawKey = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05};

        // When
        byte[] spki = AKPCOSEKey.buildSubjectPublicKeyInfo(rawKey, "ML-DSA-65");
        byte[] extracted = AKPCOSEKey.extractRawFromSubjectPublicKeyInfo(spki);

        // Then
        assertThat(extracted).isEqualTo(rawKey);
    }

    @Test
    void buildPKCS8PrivateKeyInfo_roundtrip_test() {
        // Given
        byte[] rawKey = new byte[]{0x0A, 0x0B, 0x0C, 0x0D};

        // When
        byte[] pkcs8 = AKPCOSEKey.buildPKCS8PrivateKeyInfo(rawKey, "ML-DSA-65");
        byte[] extracted = AKPCOSEKey.extractRawFromPKCS8(pkcs8);

        // Then
        assertThat(extracted).isEqualTo(rawKey);
    }

    @Test
    void buildSubjectPublicKeyInfo_with_large_key_roundtrip_test() {
        // Given - ML-DSA-65 public key size
        byte[] rawKey = new byte[1952];
        for (int i = 0; i < rawKey.length; i++) {
            rawKey[i] = (byte) (i & 0xFF);
        }

        // When
        byte[] spki = AKPCOSEKey.buildSubjectPublicKeyInfo(rawKey, "ML-DSA-65");
        byte[] extracted = AKPCOSEKey.extractRawFromSubjectPublicKeyInfo(spki);

        // Then
        assertThat(extracted).isEqualTo(rawKey);
    }

    @Test
    void buildSubjectPublicKeyInfo_all_algorithms_test() {
        // Given
        byte[] rawKey = new byte[]{0x01, 0x02, 0x03};

        // When / Then
        assertThatCode(() -> AKPCOSEKey.buildSubjectPublicKeyInfo(rawKey, "ML-DSA-44")).doesNotThrowAnyException();
        assertThatCode(() -> AKPCOSEKey.buildSubjectPublicKeyInfo(rawKey, "ML-DSA-65")).doesNotThrowAnyException();
        assertThatCode(() -> AKPCOSEKey.buildSubjectPublicKeyInfo(rawKey, "ML-DSA-87")).doesNotThrowAnyException();
    }

    @Test
    void buildSubjectPublicKeyInfo_with_unsupported_algorithm_test() {
        // Given
        byte[] rawKey = new byte[]{0x01};

        // When / Then
        assertThatThrownBy(() -> AKPCOSEKey.buildSubjectPublicKeyInfo(rawKey, "UNSUPPORTED"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @EnabledForJreRange(min = JRE.JAVA_24)
    void create_from_keyPair_test() throws Exception {
        // Given
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65");
        KeyPair keyPair = kpg.generateKeyPair();

        // When
        AKPCOSEKey coseKey = AKPCOSEKey.create(keyPair, COSEAlgorithmIdentifier.ML_DSA_65);

        // Then
        assertThat(coseKey.hasPublicKey()).isTrue();
        assertThat(coseKey.hasPrivateKey()).isTrue();
        assertThat(coseKey.getAlgorithm()).isEqualTo(COSEAlgorithmIdentifier.ML_DSA_65);
        assertThat(coseKey.getPublicKey()).isNotNull();
        assertThat(coseKey.getPrivateKey()).isNotNull();
    }

    @Test
    @EnabledForJreRange(min = JRE.JAVA_24)
    void create_from_publicKey_test() throws Exception {
        // Given
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65");
        KeyPair keyPair = kpg.generateKeyPair();

        // When
        AKPCOSEKey coseKey = AKPCOSEKey.create(keyPair.getPublic(), COSEAlgorithmIdentifier.ML_DSA_65);

        // Then
        assertThat(coseKey.hasPublicKey()).isTrue();
        assertThat(coseKey.hasPrivateKey()).isFalse();
        assertThat(coseKey.getPublicKey().getEncoded()).isEqualTo(keyPair.getPublic().getEncoded());
    }

    @Test
    @EnabledForJreRange(min = JRE.JAVA_24)
    void signAndVerify_ML_DSA_65_test() throws Exception {
        // Given
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65");
        KeyPair keyPair = kpg.generateKeyPair();
        byte[] data = "test data for ML-DSA signature".getBytes();

        // Sign with JCA directly
        Signature signer = Signature.getInstance("ML-DSA-65");
        signer.initSign(keyPair.getPrivate());
        signer.update(data);
        byte[] signature = signer.sign();

        // Create AKPCOSEKey from public key
        AKPCOSEKey coseKey = AKPCOSEKey.create(keyPair.getPublic(), COSEAlgorithmIdentifier.ML_DSA_65);

        // Verify using the verification chain (as webauthn4j would do)
        SignatureAlgorithm sigAlg = coseKey.getAlgorithm().toSignatureAlgorithm();
        Signature verifier = SignatureUtil.createSignature(sigAlg);
        verifier.initVerify(coseKey.getPublicKey());
        verifier.update(data);

        // Then
        assertThat(verifier.verify(signature)).isTrue();
    }

    @Test
    @EnabledForJreRange(min = JRE.JAVA_24)
    void signAndVerify_ML_DSA_44_test() throws Exception {
        // Given
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-44");
        KeyPair keyPair = kpg.generateKeyPair();
        byte[] data = "test data".getBytes();

        Signature signer = Signature.getInstance("ML-DSA-44");
        signer.initSign(keyPair.getPrivate());
        signer.update(data);
        byte[] signature = signer.sign();

        AKPCOSEKey coseKey = AKPCOSEKey.create(keyPair.getPublic(), COSEAlgorithmIdentifier.ML_DSA_44);

        // Verify
        SignatureAlgorithm sigAlg = coseKey.getAlgorithm().toSignatureAlgorithm();
        Signature verifier = SignatureUtil.createSignature(sigAlg);
        verifier.initVerify(coseKey.getPublicKey());
        verifier.update(data);

        // Then
        assertThat(verifier.verify(signature)).isTrue();
    }

    @Test
    @EnabledForJreRange(min = JRE.JAVA_24)
    void signAndVerify_ML_DSA_87_test() throws Exception {
        // Given
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-87");
        KeyPair keyPair = kpg.generateKeyPair();
        byte[] data = "test data".getBytes();

        Signature signer = Signature.getInstance("ML-DSA-87");
        signer.initSign(keyPair.getPrivate());
        signer.update(data);
        byte[] signature = signer.sign();

        AKPCOSEKey coseKey = AKPCOSEKey.create(keyPair.getPublic(), COSEAlgorithmIdentifier.ML_DSA_87);

        // Verify
        SignatureAlgorithm sigAlg = coseKey.getAlgorithm().toSignatureAlgorithm();
        Signature verifier = SignatureUtil.createSignature(sigAlg);
        verifier.initVerify(coseKey.getPublicKey());
        verifier.update(data);

        // Then
        assertThat(verifier.verify(signature)).isTrue();
    }

    @Test
    @EnabledForJreRange(min = JRE.JAVA_24)
    void cborRoundtrip_test() throws Exception {
        // Given
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65");
        KeyPair keyPair = kpg.generateKeyPair();
        AKPCOSEKey original = AKPCOSEKey.create(keyPair.getPublic(), COSEAlgorithmIdentifier.ML_DSA_65);

        // When - serialize to CBOR and back
        ObjectConverter objectConverter = new ObjectConverter();
        byte[] cbor = objectConverter.getCborMapper().writeValueAsBytes(original);
        COSEKey deserialized = objectConverter.getCborMapper().readValue(cbor, COSEKey.class);

        // Then
        assertThat(deserialized).isInstanceOf(AKPCOSEKey.class);
        AKPCOSEKey deserializedAkp = (AKPCOSEKey) deserialized;
        assertThat(deserializedAkp.getPub()).isEqualTo(original.getPub());
        assertThat(deserializedAkp.getAlgorithm()).isEqualTo(COSEAlgorithmIdentifier.ML_DSA_65);
        assertThat(deserializedAkp.getPublicKey().getEncoded()).isEqualTo(original.getPublicKey().getEncoded());
    }

    @Test
    void getPublicKey_returns_null_when_no_pub_test() {
        // Given
        AKPCOSEKey key = new AKPCOSEKey(null, COSEAlgorithmIdentifier.ML_DSA_65, null, null, DUMMY_PRIV);

        // Then
        assertThat(key.getPublicKey()).isNull();
    }

    @Test
    void getPrivateKey_returns_null_when_no_priv_test() {
        // Given
        AKPCOSEKey key = new AKPCOSEKey(null, COSEAlgorithmIdentifier.ML_DSA_65, null, DUMMY_PUB, null);

        // Then
        assertThat(key.getPrivateKey()).isNull();
    }

    @Test
    @EnabledForJreRange(min = JRE.JAVA_24)
    void getPublicKey_throws_when_algorithm_is_null_test() throws Exception {
        // Given
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65");
        KeyPair keyPair = kpg.generateKeyPair();
        AKPCOSEKey original = AKPCOSEKey.create(keyPair.getPublic(), COSEAlgorithmIdentifier.ML_DSA_65);
        AKPCOSEKey key = new AKPCOSEKey(null, null, null, original.getPub(), null);

        // Then
        assertThatThrownBy(key::getPublicKey).isInstanceOf(IllegalStateException.class);
    }

    @Test
    @EnabledForJreRange(min = JRE.JAVA_24)
    void getPrivateKey_throws_when_algorithm_is_null_test() throws Exception {
        // Given
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65");
        KeyPair keyPair = kpg.generateKeyPair();
        AKPCOSEKey original = AKPCOSEKey.create(keyPair, COSEAlgorithmIdentifier.ML_DSA_65);
        AKPCOSEKey key = new AKPCOSEKey(null, null, null, null, original.getPriv());

        // Then
        assertThatThrownBy(key::getPrivateKey).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void getPriv_returns_clone_test() {
        // Given
        byte[] originalPriv = new byte[]{0x0A, 0x0B, 0x0C};
        AKPCOSEKey key = new AKPCOSEKey(null, COSEAlgorithmIdentifier.ML_DSA_65, null, DUMMY_PUB, originalPriv);

        // When
        byte[] priv = key.getPriv();
        priv[0] = (byte) 0xFF;

        // Then
        assertThat(key.getPriv()[0]).isEqualTo((byte) 0x0A);
    }

    @Test
    void getPub_returns_clone_test() {
        // Given
        byte[] originalPub = new byte[]{0x01, 0x02, 0x03};
        AKPCOSEKey key = new AKPCOSEKey(null, COSEAlgorithmIdentifier.ML_DSA_65, null, originalPub, null);

        // When
        byte[] pub = key.getPub();
        pub[0] = (byte) 0xFF;

        // Then - original should not be modified
        assertThat(key.getPub()[0]).isEqualTo((byte) 0x01);
    }
}
