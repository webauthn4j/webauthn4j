package net.sharplab.springframework.security.webauthn.utils.jackson.serializer;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.sharplab.springframework.security.webauthn.test.CoreTestUtil;
import org.junit.Test;

import java.io.IOException;
import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for CertPathSerializer
 */
public class CertPathSerializerTest {

    @Test
    public void test() throws CertificateException, IOException {
        ObjectMapper objectMapper = CoreTestUtil.createCBORMapper();

        //Given
        Certificate cert1 = CoreTestUtil.createFirefoxSWTokenAttestationCertificate();
        Certificate cert2 = CoreTestUtil.createFirefoxSWTokenAttestationCertificate();

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        CertPath certPath = certificateFactory.generateCertPath(Arrays.asList(cert1, cert2));

        byte[] result = objectMapper.writeValueAsBytes(certPath);

        //When
        CertPath deserialized = objectMapper.readValue(result, CertPath.class);

        //Then
        assertThat(deserialized.getCertificates().toArray()).containsExactly(cert1, cert2);

    }
}
