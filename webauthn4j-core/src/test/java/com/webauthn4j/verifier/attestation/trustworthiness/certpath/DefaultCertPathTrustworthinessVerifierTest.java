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

package com.webauthn4j.verifier.attestation.trustworthiness.certpath;

import com.webauthn4j.anchor.TrustAnchorRepository;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.test.TestAttestationStatementUtil;
import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.util.Base64Util;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.verifier.exception.CertificateException;
import com.webauthn4j.verifier.exception.TrustAnchorNotFoundException;
import org.junit.jupiter.api.Test;

import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DefaultCertPathTrustworthinessVerifierTest {

    private final TrustAnchorRepository trustAnchorRepository = mock(TrustAnchorRepository.class);
    private final DefaultCertPathTrustworthinessVerifier target = new DefaultCertPathTrustworthinessVerifier(trustAnchorRepository);
    private final AAGUID aaguid = new AAGUID(UUID.randomUUID());

    @Test
    void verify_u2F_test() {

        Set<TrustAnchor> trustAnchors = CertificateUtil.generateTrustAnchors(
                Collections.singletonList(TestAttestationUtil.load2tierTestRootCACertificate()));
        when(trustAnchorRepository.find((byte[])any())).thenReturn(trustAnchors);

        CertificateBaseAttestationStatement attestationStatement = TestAttestationStatementUtil.createFIDOU2FAttestationStatement(TestAttestationUtil.load2tierTestAttestationCertificatePath());
        target.verify(aaguid, attestationStatement);
    }

    @Test
    void verify_packed_test() {

        Set<TrustAnchor> trustAnchors = CertificateUtil.generateTrustAnchors(
                Collections.singletonList(TestAttestationUtil.load3tierTestRootCACertificate()));
        when(trustAnchorRepository.find((AAGUID) any())).thenReturn(trustAnchors);

        CertificateBaseAttestationStatement attestationStatement = TestAttestationStatementUtil.createBasicPackedAttestationStatement(TestAttestationUtil.load3tierTestAttestationCertificatePath());
        target.verify(aaguid, attestationStatement);
    }

    @Test
    void verify_with_empty_trustAnchors_test() {

        Set<TrustAnchor> trustAnchors = Collections.emptySet();
        when(trustAnchorRepository.find(aaguid)).thenReturn(trustAnchors);

        CertificateBaseAttestationStatement attestationStatement = TestAttestationStatementUtil.createFIDOU2FAttestationStatement(TestAttestationUtil.load2tierTestAttestationCertificatePath());
        assertThrows(TrustAnchorNotFoundException.class,
                () -> target.verify(aaguid, attestationStatement)
        );
    }

    @Test
    void verify_with_trustAnchor_which_equals_to_x5C() {

        X509Certificate attestationCertificate = TestAttestationUtil.load3tierTestAttestationCertificatePath().getEndEntityAttestationCertificate().getCertificate();
        X509Certificate attestationCertificateLoadedAnotherTime = TestAttestationUtil.load3tierTestAttestationCertificatePath().getEndEntityAttestationCertificate().getCertificate();

        Set<TrustAnchor> trustAnchors = CertificateUtil.generateTrustAnchors(Collections.singletonList(attestationCertificate));
        when(trustAnchorRepository.find((AAGUID) any())).thenReturn(trustAnchors);

        AttestationCertificatePath attestationCertificatePath = new AttestationCertificatePath(attestationCertificateLoadedAnotherTime, Collections.emptyList());
        CertificateBaseAttestationStatement attestationStatement = TestAttestationStatementUtil.createBasicPackedAttestationStatement(attestationCertificatePath);
        target.verify(aaguid, attestationStatement);
    }

    @Test
    void verify_full_chain_test() {

        Set<TrustAnchor> trustAnchors = CertificateUtil.generateTrustAnchors(
                Collections.singletonList(TestAttestationUtil.load3tierTestRootCACertificate()));
        when(trustAnchorRepository.find(aaguid)).thenReturn(trustAnchors);

        AttestationCertificatePath attestationCertificatePath
                = new AttestationCertificatePath(Arrays.asList(
                TestAttestationUtil.load3tierTestAuthenticatorAttestationCertificate(),
                TestAttestationUtil.load3tierTestIntermediateCACertificate(),
                TestAttestationUtil.load3tierTestRootCACertificate()));

        CertificateBaseAttestationStatement attestationStatement = TestAttestationStatementUtil.createBasicPackedAttestationStatement(attestationCertificatePath);
        target.setFullChainProhibited(true);
        assertThrows(CertificateException.class,
                () -> target.verify(aaguid, attestationStatement)
        );
    }


    @Test
    void getter_setter_test() {
        target.setFullChainProhibited(true);
        assertThat(target.isFullChainProhibited()).isTrue();
        target.setPolicyQualifiersRejected(true);
        assertThat(target.isPolicyQualifiersRejected()).isTrue();
        target.setRevocationCheckEnabled(true);
        assertThat(target.isRevocationCheckEnabled()).isTrue();
    }

    @Test
    void extractSubjectKeyIdentifier_test() {
        X509Certificate x509Certificate = CertificateUtil.generateX509Certificate(Base64Util.decode("MIIEKzCCAhOgAwIBAgIBATANBgkqhkiG9w0BAQUFADCBoTEYMBYGA1UEAwwPRklETzIgVEVTVCBST09UMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMB4XDTE4MDMxNjE0MzUyN1oXDTI4MDMxMzE0MzUyN1owgawxIzAhBgNVBAMMGkZJRE8yIEJBVENIIEtFWSBwcmltZTI1NnYxMTEwLwYJKoZIhvcNAQkBFiJjb25mb3JtYW5jZS10b29sc0BmaWRvYWxsaWFuY2Uub3JnMRYwFAYDVQQKDA1GSURPIEFsbGlhbmNlMQwwCgYDVQQLDANDV0cxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJNWTESMBAGA1UEBwwJV2FrZWZpZWxkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETzpeXqtsH7yul/bfZEmWdix773IAQCp2xvIw9lVvF6qZm1l/xL9Qiq+OnvDNAT9aub0nkUvwgEN4y8yxG4m1RqMsMCowCQYDVR0TBAIwADAdBgNVHQ4EFgQUVk33wPjGVbahH2xNGfO/QeL9AXkwDQYJKoZIhvcNAQEFBQADggIBAI+/jI31FB+8J2XxzBXMuI4Yg+vAtq07ABHJqnQpUmt8lpOzmvJ0COKcwtq/7bpsgSVBJ26zhnyWcm1q8V0ZbxUvN2kH8N7nteIGn+CJOJkHDII+IbiH4+TUQCJjuCB52duUWL0fGVw2R13J6V+K7U5r0OWBzmtmwwiRVTggVbjDpbx2oqGAwzupG3RmBFDX1M92s3tgywnLr+e6NZal5yZdS8VblJGjswDZbdY+Qobo2DCN6vxvn5TVkukAHiArjpBBpAmuQfKa52vqSCYRpTCm57fQUZ1c1n29OsvDw1x9ckyH8j/9Xgk0AG+MlQ9Rdg3hCb7LkSPvC/zYDeS2Cj/yFw6OWahnnIRwO6t4UtLuRAkLrjP1T7nk0zu1whwj7YEwtva45niWWh6rdyg/SZlfsph3o/MZN5DwKaSrUaEO6b+numELH5GWjjiPgfgPKkIof+D40xaKUFBpNJzorQkAZCJWuHvXRpBZWFVh/UhNlGhX0mhz2yFlBrujYa9BgvIkdJ8Keok6qfAn+r5EEFXcSI8vGY7OEF01QKXVpu8+FW0uSxtQ991AcFD6KjvR51l7e61visUgduhZRIq9bYzeCIxnK5Jhm3o/NJE2bOp2NmVwVe4kjuJX87wo3Ba41bXgwIpdiLWyWJhSHPmJI/1ibRTZ5XO92xbPPSnnkXrF"));
        byte[] subjectKeyIdentifier =  DefaultCertPathTrustworthinessVerifier.extractSubjectKeyIdentifier(x509Certificate);
        assertThat(subjectKeyIdentifier).asHexString().isEqualTo("564DF7C0F8C655B6A11F6C4D19F3BF41E2FD0179");
    }
}