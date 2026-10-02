package com.webauthn4j.data.attestation.authenticator;

import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.COSEKeyType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;

import java.security.KeyPairGenerator;
import java.security.KeyPair;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@EnabledForJreRange(min = JRE.JAVA_24)
class AKPCOSEKeyTest {

    @Test
    void getPrivateKey_throws_without_bc() {
        // Given - AKPCOSEKey with a 32-byte seed as priv
        byte[] dummyPub = new byte[1952];
        byte[] seed = new byte[32];
        AKPCOSEKey coseKey = new AKPCOSEKey(null, COSEAlgorithmIdentifier.ML_DSA_65, null, dummyPub, seed);

        // Then - getPrivateKey requires BC to expand seed, should throw without it
        assertThatThrownBy(coseKey::getPrivateKey).isInstanceOf(UnsupportedOperationException.class);
    }
}
