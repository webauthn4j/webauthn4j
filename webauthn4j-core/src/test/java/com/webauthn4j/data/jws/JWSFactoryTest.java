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

package com.webauthn4j.data.jws;

import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.util.ECUtil;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JWSFactoryTest {

    private final JWSFactory target = new JWSFactory();

    @Test
    void create_with_private_key_test() {
        JWSHeader header = new JWSHeader(JWAIdentifier.ES256, CertificateUtil.generateCertPath(Collections.emptyList()));
        Payload payload = new Payload();
        KeyPair keyPair = ECUtil.createKeyPair();
        JWS<Payload> jws = target.create(header, payload, keyPair.getPrivate());
        assertThat(jws).isNotNull();
    }

    @Test
    void create_with_signature_test() {
        JWSHeader header = new JWSHeader(JWAIdentifier.ES256, CertificateUtil.generateCertPath(Collections.emptyList()));
        Payload payload = new Payload();
        byte[] signature = new byte[32];
        JWS<Payload> jws = target.create(header, payload, signature);
        assertThat(jws).isNotNull();
    }

    @Test
    void create_with_alg_null_test() {
        JWSHeader header = new JWSHeader(null, CertificateUtil.generateCertPath(Collections.emptyList()));
        Payload payload = new Payload();
        PrivateKey privateKey = ECUtil.createKeyPair().getPrivate();
        assertThatThrownBy(() -> target.create(header, payload, privateKey)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void signature_length_es256_test() {
        JWSHeader header = new JWSHeader(JWAIdentifier.ES256, CertificateUtil.generateCertPath(Collections.emptyList()));
        Payload payload = new Payload();
        KeyPair keyPair = ECUtil.createKeyPair();
        JWS<Payload> jws = target.create(header, payload, keyPair.getPrivate());
        assertThat(jws.getSignature()).hasSize(64); // RFC 7518 Section 3.4: ES256 = 32+32 bytes
    }

    @Test
    void signature_length_es384_test() {
        JWSHeader header = new JWSHeader(JWAIdentifier.ES384, CertificateUtil.generateCertPath(Collections.emptyList()));
        Payload payload = new Payload();
        KeyPair keyPair = ECUtil.createKeyPair(ECUtil.P_384_SPEC);
        JWS<Payload> jws = target.create(header, payload, keyPair.getPrivate());
        assertThat(jws.getSignature()).hasSize(96); // RFC 7518 Section 3.4: ES384 = 48+48 bytes
    }

    @Test
    void signature_length_es512_test() {
        JWSHeader header = new JWSHeader(JWAIdentifier.ES512, CertificateUtil.generateCertPath(Collections.emptyList()));
        Payload payload = new Payload();
        KeyPair keyPair = ECUtil.createKeyPair(ECUtil.P_521_SPEC);
        JWS<Payload> jws = target.create(header, payload, keyPair.getPrivate());
        assertThat(jws.getSignature()).hasSize(132); // RFC 7518 Section 3.4: ES512 = 66+66 bytes
    }


    private static class Payload {
        private String dummy;

        public String getDummy() {
            return dummy;
        }

        public void setDummy(String dummy) {
            this.dummy = dummy;
        }
    }

}