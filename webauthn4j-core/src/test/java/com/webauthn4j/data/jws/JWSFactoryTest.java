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
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledForJreRange;
import org.junit.jupiter.api.condition.JRE;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.CertPath;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;

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
    @EnabledForJreRange(min = JRE.JAVA_24)
    void create_with_ml_dsa_65_private_key_test() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65");
        KeyPair keyPair = kpg.generateKeyPair();
        JWSHeader header = new JWSHeader(JWAIdentifier.ML_DSA_65, CertificateUtil.generateCertPath(Collections.emptyList()));
        Payload payload = new Payload();
        JWS<Payload> jws = target.create(header, payload, keyPair.getPrivate());
        assertThat(jws).isNotNull();
        assertThat(jws.getSignature()).isNotEmpty();
    }

    @Test
    @EnabledForJreRange(min = JRE.JAVA_24)
    void create_and_verify_ml_dsa_65_roundtrip_test() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-DSA-65");
        KeyPair keyPair = kpg.generateKeyPair();

        // Create a self-signed ML-DSA-65 certificate via Bouncy Castle
        X500Principal subject = new X500Principal("CN=Test ML-DSA");
        ContentSigner signer = new JcaContentSignerBuilder("ML-DSA-65").build(keyPair.getPrivate());
        X509CertificateHolder holder = new JcaX509v3CertificateBuilder(
                subject, BigInteger.ONE,
                Date.from(Instant.parse("2000-01-01T00:00:00Z")),
                Date.from(Instant.parse("2099-12-31T23:59:59Z")),
                subject, keyPair.getPublic()
        ).build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
        CertPath certPath = CertificateUtil.generateCertPath(Collections.singletonList(cert));

        // Create JWS signed with ML-DSA-65
        JWSHeader header = new JWSHeader(JWAIdentifier.ML_DSA_65, certPath);
        Payload payload = new Payload();
        JWS<Payload> jws = target.create(header, payload, keyPair.getPrivate());

        // Verify the signature
        assertThat(jws.isValidSignature()).isTrue();
    }

    @Test
    void create_and_verify_es256_roundtrip_test() throws Exception {
        KeyPair keyPair = ECUtil.createKeyPair();

        // Create a self-signed ES256 certificate via Bouncy Castle
        X500Principal subject = new X500Principal("CN=Test ES256");
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
        X509CertificateHolder holder = new JcaX509v3CertificateBuilder(
                subject, BigInteger.ONE,
                Date.from(Instant.parse("2000-01-01T00:00:00Z")),
                Date.from(Instant.parse("2099-12-31T23:59:59Z")),
                subject, keyPair.getPublic()
        ).build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
        CertPath certPath = CertificateUtil.generateCertPath(Collections.singletonList(cert));

        // Create JWS signed with ES256
        JWSHeader header = new JWSHeader(JWAIdentifier.ES256, certPath);
        Payload payload = new Payload();
        JWS<Payload> jws = target.create(header, payload, keyPair.getPrivate());

        // Verify the signature
        assertThat(jws.isValidSignature()).isTrue();
    }

    @Test
    void create_with_alg_null_test() {
        JWSHeader header = new JWSHeader(null, CertificateUtil.generateCertPath(Collections.emptyList()));
        Payload payload = new Payload();
        PrivateKey privateKey = ECUtil.createKeyPair().getPrivate();
        assertThatThrownBy(() -> target.create(header, payload, privateKey)).isInstanceOf(IllegalArgumentException.class);
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