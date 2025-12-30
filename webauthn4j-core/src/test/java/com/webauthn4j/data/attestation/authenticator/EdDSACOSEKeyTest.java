package com.webauthn4j.data.attestation.authenticator;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.COSEKeyType;
import com.webauthn4j.util.HexUtil;
import com.webauthn4j.verifier.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;
import test.EdDSAUtil;

import java.security.KeyPair;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.NamedParameterSpec;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EdDSACOSEKeyTest {

    @Test
    void publicKey_test(){
        KeyPair keyPair = EdDSAUtil.createKeyPair();
        COSEKey coseKey = EdDSACOSEKey.create((EdECPublicKey) keyPair.getPublic());
        assertThat(coseKey.hasPublicKey()).isTrue();
        assertThat(coseKey.hasPrivateKey()).isFalse();
        assertThat(coseKey.getPublicKey()).isNotNull();
        assertThat(coseKey.getPrivateKey()).isNull();
        assertThat(coseKey.getPublicKey().getEncoded()).isEqualTo(keyPair.getPublic().getEncoded());
    }

    @Test
    void privateKey_test(){
        KeyPair keyPair = EdDSAUtil.createKeyPair();
        COSEKey coseKey = EdDSACOSEKey.create((EdECPrivateKey) keyPair.getPrivate());
        assertThat(coseKey.hasPublicKey()).isFalse();
        assertThat(coseKey.hasPrivateKey()).isTrue();
        assertThat(coseKey.getPublicKey()).isNull();
        assertThat(coseKey.getPrivateKey()).isNotNull();
        assertThat(coseKey.getPrivateKey().getEncoded()).isEqualTo(keyPair.getPrivate().getEncoded());
    }

    @Test
    void keyPair_test(){
        KeyPair keyPair = EdDSAUtil.createKeyPair();
        COSEKey coseKey = EdDSACOSEKey.create(keyPair);
        assertThat(coseKey.hasPublicKey()).isTrue();
        assertThat(coseKey.hasPrivateKey()).isTrue();
        assertThat(coseKey.getPublicKey()).isNotNull();
        assertThat(coseKey.getPrivateKey()).isNotNull();
        assertThat(coseKey.getPublicKey().getEncoded()).isEqualTo(keyPair.getPublic().getEncoded());
        assertThat(coseKey.getPrivateKey().getEncoded()).isEqualTo(keyPair.getPrivate().getEncoded());
    }

    @Test
    void getKeyType_test() {
        EdDSACOSEKey target = EdDSACOSEKey.create(EdDSAUtil.createKeyPair());
        assertThat(target.getKeyType()).isEqualTo(COSEKeyType.OKP);
    }

    @Test
    void validate_test() {
        EdDSACOSEKey target = EdDSACOSEKey.create(EdDSAUtil.createKeyPair());
        target.validate();
    }


    @Test
    void validate_with_null_curve_test() {
        EdDSACOSEKey instance = EdDSACOSEKey.create((EdECPublicKey) EdDSAUtil.createKeyPair().getPublic());
        EdDSACOSEKey target = new EdDSACOSEKey(
                null,
                instance.getAlgorithm(),
                null,
                null,
                instance.getX(),
                instance.getD()
        );
        assertThrows(ConstraintViolationException.class,
                target::validate
        );
    }

    @Test
    void validate_with_non_Ed25519_curve_test() {
        EdDSACOSEKey instance = EdDSACOSEKey.create((EdECPublicKey) EdDSAUtil.createKeyPair().getPublic());
        EdDSACOSEKey target = new EdDSACOSEKey(
                null,
                instance.getAlgorithm(),
                null,
                Curve.SECP256R1,
                instance.getX(),
                instance.getD()
        );
        assertThrows(ConstraintViolationException.class,
                target::validate
        );
    }

    @Test
    void validate_with_null_x_and_null_d_test() {
        EdDSACOSEKey instance = EdDSACOSEKey.create((EdECPublicKey) EdDSAUtil.createKeyPair().getPublic());
        EdDSACOSEKey target = new EdDSACOSEKey(
                null,
                instance.getAlgorithm(),
                null,
                instance.getCurve(),
                null,
                null
        );
        assertThrows(ConstraintViolationException.class,
                target::validate
        );
    }

    @Test
    void validate_with_null_x_test() { //TODO: revisit
        EdDSACOSEKey instance = EdDSACOSEKey.create((EdECPublicKey) EdDSAUtil.createKeyPair().getPublic());
        EdDSACOSEKey target = new EdDSACOSEKey(
                null,
                instance.getAlgorithm(),
                null,
                instance.getCurve(),
                null,
                instance.getD()
        );
        assertThrows(ConstraintViolationException.class,
                target::validate
        );
    }

    @Test
    void validate_with_null_algorithm_test() {
        EdDSACOSEKey instance = EdDSACOSEKey.create((EdECPublicKey) EdDSAUtil.createKeyPair().getPublic());
        EdDSACOSEKey target = new EdDSACOSEKey(
                null,
                null,
                null,
                instance.getCurve(),
                instance.getX(),
                instance.getD()
        );
        assertThatCode(target::validate).doesNotThrowAnyException();
    }

    @Test
    void validate_with_new_instance_EdDSA_algorithm_test() {
        EdDSACOSEKey instance = EdDSACOSEKey.create((EdECPublicKey) EdDSAUtil.createKeyPair().getPublic());
        EdDSACOSEKey target = new EdDSACOSEKey(
                null,
                COSEAlgorithmIdentifier.create(-8),
                null,
                instance.getCurve(),
                instance.getX(),
                instance.getD()
        );
        assertThatCode(target::validate).doesNotThrowAnyException();
    }

    @Test
    void validate_with_non_EdDSA_algorithm_test() {
        EdDSACOSEKey instance = EdDSACOSEKey.create((EdECPublicKey) EdDSAUtil.createKeyPair().getPublic());
        EdDSACOSEKey target = new EdDSACOSEKey(
            null,
                COSEAlgorithmIdentifier.ES256,
                null,
                instance.getCurve(),
                instance.getX(),
                instance.getD()
        );
        assertThrows(ConstraintViolationException.class,
                target::validate
        );
    }


    @Test
    void getCurve_not_supported_curve_test(){
        assertThatThrownBy(()->EdDSACOSEKey.getCurve(NamedParameterSpec.X25519)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void decode_test(){
        COSEKey coseKey = new ObjectConverter().getCborConverter().readValue(HexUtil.decode("A4010103272006215820789A234CA91653BF7FB573C9FA519C27C09F1156C1779634E58C8888E304F87AA16B6372656450726F7465637402"), COSEKey.class);
        assertThat(coseKey).isInstanceOf(EdDSACOSEKey.class);
        EdDSACOSEKey edDSACOSEKey = (EdDSACOSEKey) coseKey;
        assertThat(edDSACOSEKey.getX()).isEqualTo(HexUtil.decode("789A234CA91653BF7FB573C9FA519C27C09F1156C1779634E58C8888E304F87A"));
        assertThat(edDSACOSEKey.getD()).isNull();
        assertThat(edDSACOSEKey.getAlgorithm()).isEqualTo(COSEAlgorithmIdentifier.EdDSA);
        assertThat(edDSACOSEKey.getCurve()).isEqualTo(Curve.ED25519);
    }

    @Test
    void equals_hashCode_test(){
        KeyPair keyPair = EdDSAUtil.createKeyPair();
        COSEKey instanceA = EdDSACOSEKey.create(keyPair);
        COSEKey instanceB = EdDSACOSEKey.create(keyPair);
        assertThat(instanceA)
                .isEqualTo(instanceB)
                .hasSameHashCodeAs(instanceB);
    }

    @Test
    void toString_test(){
        COSEKey coseKey = new ObjectConverter().getCborConverter().readValue(HexUtil.decode("A4010103272006215820789A234CA91653BF7FB573C9FA519C27C09F1156C1779634E58C8888E304F87AA16B6372656450726F7465637402"), COSEKey.class);
        assertThat(coseKey).isInstanceOf(EdDSACOSEKey.class);
        EdDSACOSEKey edDSACOSEKey = (EdDSACOSEKey) coseKey;
        assertThat(edDSACOSEKey).hasToString("EdDSACOSEKey(keyId=null, alg=EdDSA, curve=ED25519, x=789A234CA91653BF7FB573C9FA519C27C09F1156C1779634E58C8888E304F87A, d=null)");
    }

}