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

package com.webauthn4j.converter;

import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.response.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.test.TestUtil;
import org.junit.Test;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

public class AttestationCertificatePathConverterTest {

    private CborConverter cborConverter = new CborConverter();

    @Test
    public void test(){
        AttestationCertificatePath attestationCertificatePath = new AttestationCertificatePath(Collections.singletonList(TestUtil.load2tierTestAuthenticatorAttestationCertificate()));
        byte[] cbor = cborConverter.writeValueAsBytes(attestationCertificatePath);
        AttestationCertificatePath restored = cborConverter.readValue(cbor, AttestationCertificatePath.class);
        assertThat(restored).isEqualTo(attestationCertificatePath);
    }
}
