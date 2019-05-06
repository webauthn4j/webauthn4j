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

package com.webauthn4j.data.jws;

import com.webauthn4j.test.KeyUtil;
import com.webauthn4j.test.TestAttestationUtil;
import org.junit.jupiter.api.Test;

import java.io.Serializable;
import java.security.KeyPair;

import static org.assertj.core.api.Assertions.assertThat;

class JWSFactoryTest {

    private JWSFactory target = new JWSFactory();

    @Test
    void create_with_private_key_test(){
        JWSHeader header = new JWSHeader(JWAIdentifier.ES256, TestAttestationUtil.load3tierTestAttestationCertificatePath());
        Payload payload = new Payload();
        KeyPair keyPair = KeyUtil.createECKeyPair();
        JWS<Payload> jws = target.create(header, payload, keyPair.getPrivate());
        assertThat(jws).isNotNull();
    }

    @Test
    void create_with_signature_test(){
        JWSHeader header = new JWSHeader(JWAIdentifier.ES256, TestAttestationUtil.load3tierTestAttestationCertificatePath());
        Payload payload = new Payload();
        byte[] signature = new byte[32];
        JWS<Payload> jws = target.create(header, payload, signature);
        assertThat(jws).isNotNull();
    }

    private class Payload implements Serializable {
        private String dummy;

        public String getDummy() {
            return dummy;
        }

        public void setDummy(String dummy) {
            this.dummy = dummy;
        }
    }

}