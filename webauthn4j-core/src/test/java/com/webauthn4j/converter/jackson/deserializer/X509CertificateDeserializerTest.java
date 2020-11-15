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

package com.webauthn4j.converter.jackson.deserializer;

import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.test.TestAttestationUtil;
import org.junit.jupiter.api.Test;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SuppressWarnings("ConstantConditions")
class X509CertificateDeserializerTest {


    @Test
    void deserialize_test() throws CertificateEncodingException {
        ObjectConverter objectConverter = new ObjectConverter();
        CborConverter cborConverter = objectConverter.getCborConverter();

        Map<String, byte[]> source = new HashMap<>();
        source.put("certificate", TestAttestationUtil.load2tierTestAuthenticatorAttestationCertificate().getEncoded());
        byte[] input = cborConverter.writeValueAsBytes(source);

        X509CertificateDeserializerTestData result = cborConverter.readValue(input, X509CertificateDeserializerTestData.class);
        assertThat(result.getCertificate()).isInstanceOf(X509Certificate.class);
    }

    @Test
    void deserialize_empty_byte_array_test() {
        ObjectConverter objectConverter = new ObjectConverter();
        CborConverter cborConverter = objectConverter.getCborConverter();

        Map<String, byte[]> source = new HashMap<>();
        source.put("certificate", new byte[0]);
        byte[] input = cborConverter.writeValueAsBytes(source);

        X509CertificateDeserializerTestData result = cborConverter.readValue(input, X509CertificateDeserializerTestData.class);
        assertThat(result.getCertificate()).isNull();
    }
}
