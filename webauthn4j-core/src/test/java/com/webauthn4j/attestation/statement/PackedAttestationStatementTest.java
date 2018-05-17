package com.webauthn4j.attestation.statement;

import com.webauthn4j.test.TestUtil;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.junit.Test;

import java.security.cert.CertPath;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

public class PackedAttestationStatementTest {

    @Test
    public void validate_test() {
        PackedAttestationStatement packedAttestationStatement = TestUtil.createBasicPackedAttestationStatement();
        packedAttestationStatement.validate();
    }

    @Test(expected = ConstraintViolationException.class)
    public void validate_invalid_instance_test() {
        PackedAttestationStatement packedAttestationStatement = new PackedAttestationStatement();
        packedAttestationStatement.validate();
    }

    @Test(expected = IllegalStateException.class)
    public void getEndEntityCertificate_from_invalid_instance_test() {
        CertPath emptyCertPath = CertificateUtil.generateCertPath(Collections.emptyList());
        PackedAttestationStatement packedAttestationStatement =
                new PackedAttestationStatement(COSEAlgorithmIdentifier.ES256, new byte[32], emptyCertPath, null);
        packedAttestationStatement.getEndEntityCertificate();
    }

    @Test
    public void equals_and_hashCode_test() {
        PackedAttestationStatement packedAttestationStatementA = TestUtil.createBasicPackedAttestationStatement();
        PackedAttestationStatement packedAttestationStatementB = TestUtil.createBasicPackedAttestationStatement();
        assertThat(packedAttestationStatementA).isEqualTo(packedAttestationStatementB);
        assertThat(packedAttestationStatementA).hasSameHashCodeAs(packedAttestationStatementB);
    }
}
