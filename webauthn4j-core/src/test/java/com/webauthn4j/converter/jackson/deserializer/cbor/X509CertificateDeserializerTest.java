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

package com.webauthn4j.converter.jackson.deserializer.cbor;

import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.test.TestAttestationUtil;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.exc.MismatchedInputException;
import tools.jackson.dataformat.cbor.CBORMapper;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Test for X509CertificateDeserializer
 */
@SuppressWarnings("ConstantConditions")
class X509CertificateDeserializerTest {

    private final ObjectConverter objectConverter = new ObjectConverter();
    private final CBORMapper cborMapper = objectConverter.getCborMapper();

    @Test
    void shouldDeserializeX509Certificate() throws CertificateEncodingException {
        //Given
        Map<String, byte[]> source = new HashMap<>();
        source.put("certificate", TestAttestationUtil.load2tierTestAuthenticatorAttestationCertificate().getEncoded());
        byte[] input = cborMapper.writeValueAsBytes(source);

        //When
        X509CertificateDeserializerTestData result = cborMapper.readValue(input, X509CertificateDeserializerTestData.class);

        //Then
        assertThat(result.getCertificate()).isInstanceOf(X509Certificate.class);
    }

    @Test
    void shouldReturnNullForEmptyByteArray() {
        //Given
        Map<String, byte[]> source = new HashMap<>();
        source.put("certificate", new byte[0]);
        byte[] input = cborMapper.writeValueAsBytes(source);

        //When
        X509CertificateDeserializerTestData result = cborMapper.readValue(input, X509CertificateDeserializerTestData.class);

        //Then
        assertThat(result.getCertificate()).isNull();
    }

    @Test
    void shouldThrowExceptionForInvalidInput() {
        //Given
        byte[] invalidCbor = new byte[]{0x00, 0x01, 0x02}; // Invalid CBOR data

        //Then
        assertThatThrownBy(() -> cborMapper.readValue(invalidCbor, X509CertificateDeserializerTestData.class))
                .isInstanceOf(MismatchedInputException.class);
    }

    @Test
    void shouldThrowExceptionForNullInput() {
        //Then
        assertThatThrownBy(() -> cborMapper.readValue((byte[])null, X509CertificateDeserializerTestData.class))
                .isInstanceOf(IllegalArgumentException.class);
    }

    static class X509CertificateDeserializerTestData {

        private X509Certificate certificate;

        public X509Certificate getCertificate() {
            return certificate;
        }

        public void setCertificate(X509Certificate certificate) {
            this.certificate = certificate;
        }
    }

}
