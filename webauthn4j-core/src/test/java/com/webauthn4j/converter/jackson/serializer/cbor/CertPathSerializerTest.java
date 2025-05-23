/*
 * Copyright 2002-2018 the original author or authors.
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

package com.webauthn4j.converter.jackson.serializer.cbor;

import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.test.TestAttestationUtil;
import org.junit.jupiter.api.Test;

import java.security.cert.CertPath;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Test for CertPathSerializer
 */
class CertPathSerializerTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final CborConverter cborConverter = objectConverter.getCborConverter();

    @SuppressWarnings("ConstantConditions")
    @Test
    void shouldSerializeAndDeserializeCertPath() throws CertificateException {
        //Given
        Certificate cert1 = TestAttestationUtil.loadFirefoxSWTokenAttestationCertificate();
        Certificate cert2 = TestAttestationUtil.loadFirefoxSWTokenAttestationCertificate();
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        CertPath certPath = certificateFactory.generateCertPath(Arrays.asList(cert1, cert2));

        //When
        byte[] result = cborConverter.writeValueAsBytes(certPath);
        CertPath restored = cborConverter.readValue(result, CertPath.class);

        //Then
        assertThat(restored.getCertificates().toArray()).containsExactly(cert1, cert2);
    }

    @Test
    void shouldHandleNullCertPath() {
        //Given
        TestDto testDto = new TestDto();
        testDto.setCertPath(null);

        //When/Then
        assertThatCode(() -> cborConverter.writeValueAsBytes(testDto)).doesNotThrowAnyException();
    }

    static class TestDto {
        private CertPath certPath;

        public CertPath getCertPath() {
            return certPath;
        }

        public void setCertPath(CertPath certPath) {
            this.certPath = certPath;
        }
    }

}
