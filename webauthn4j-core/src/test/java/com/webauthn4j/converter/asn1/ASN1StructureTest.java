package com.webauthn4j.converter.asn1;

import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.verifier.internal.asn1.ASN1Structure;
import org.junit.jupiter.api.Test;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

class ASN1StructureTest {

    @Test
    void shouldParseX509Certificate() throws CertificateEncodingException {
        X509Certificate attestationCertificate = TestAttestationUtil.load3tierTestAuthenticatorAttestationCertificate();
        ASN1Structure structure = ASN1Structure.parse(attestationCertificate.getEncoded());

        // Verify the structure is not null and has expected properties
        assertThat(structure).isNotNull();
        assertThat(structure.size()).isGreaterThan(0);

        // X.509 certificates should have a sequence as the top-level structure
        assertThat(structure.getTag().isConstructed()).isTrue();
    }

    @Test
    void shouldThrowExceptionWhenParsingInvalidData() {
        byte[] invalidData = new byte[]{0x00, 0x01, 0x02};
        assertThatThrownBy(() -> ASN1Structure.parse(invalidData))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
