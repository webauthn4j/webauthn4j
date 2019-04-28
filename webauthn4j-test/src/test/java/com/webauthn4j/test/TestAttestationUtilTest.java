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

package com.webauthn4j.test;

import org.junit.jupiter.api.Test;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

class TestAttestationUtilTest {

    @Test
    void loadTestAuthenticatorAttestationPrivateKey_test() {
        PrivateKey privateKey = TestAttestationUtil.load3tierTestAuthenticatorAttestationPrivateKey();
        assertThat(privateKey).isNotNull();
    }

    @Test
    void createTPMAttestationCertificate_test(){
        PrivateKey rootCAPrivateKey = TestAttestationUtil.load3tierTestRootCAPrivateKey();
        X509Certificate intermediateCertificate = TestAttestationUtil.load3tierTestIntermediateCACertificate();
        PublicKey authenticatorPublicKey = TestAttestationUtil.load3tierTestAuthenticatorAttestationCertificate().getPublicKey();
        X509Certificate x509Certificate = TestAttestationUtil.createTPMAttestationCertificate(intermediateCertificate, rootCAPrivateKey, authenticatorPublicKey);
        assertThat(x509Certificate).isNotNull();
    }
}
