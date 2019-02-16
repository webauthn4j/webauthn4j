/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.converter.jackson.deserializer;

import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class X509CertificateDeserializerTest {

    @Test
    public void deserialize_test() throws CertificateEncodingException {
        CborConverter cborConverter = new CborConverter();

        Map<String, byte[]> source = new HashMap<>();
        source.put("certificate", TestUtil.load2tierTestAuthenticatorAttestationCertificate().getEncoded());
        byte[] input = cborConverter.writeValueAsBytes(source);

        X509CertificateDeserializerTestData result = cborConverter.readValue(input, X509CertificateDeserializerTestData.class);
        assertThat(result.getCertificate()).isInstanceOf(X509Certificate.class);
    }

    @Test
    public void deserialize_empty_byte_array_test() {
        CborConverter cborConverter = new CborConverter();

        Map<String, byte[]> source = new HashMap<>();
        source.put("certificate", new byte[0]);
        byte[] input = cborConverter.writeValueAsBytes(source);

        X509CertificateDeserializerTestData result = cborConverter.readValue(input, X509CertificateDeserializerTestData.class);
        assertThat(result.getCertificate()).isNull();
    }
}
