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

package com.webauthn4j.validator.attestation.trustworthiness.certpath;

import com.webauthn4j.anchor.TrustAnchorRepository;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.test.TestAttestationStatementUtil;
import com.webauthn4j.test.TestAttestationUtil;
import com.webauthn4j.util.CertificateUtil;
import com.webauthn4j.validator.exception.CertificateException;
import com.webauthn4j.validator.exception.TrustAnchorNotFoundException;
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

class DefaultCertPathTrustworthinessValidatorTest {

    private final TrustAnchorRepository trustAnchorRepository = mock(TrustAnchorRepository.class);
    private final DefaultCertPathTrustworthinessValidator target = new DefaultCertPathTrustworthinessValidator(trustAnchorRepository);
    private final AAGUID aaguid = new AAGUID(UUID.randomUUID());

    @Test
    void validate_u2f_test() {

        Set<TrustAnchor> trustAnchors = CertificateUtil.generateTrustAnchors(
                Collections.singletonList(TestAttestationUtil.load2tierTestRootCACertificate()));
        when(trustAnchorRepository.find((byte[])any())).thenReturn(trustAnchors);

        CertificateBaseAttestationStatement attestationStatement = TestAttestationStatementUtil.createFIDOU2FAttestationStatement(TestAttestationUtil.load2tierTestAttestationCertificatePath());
        target.validate(aaguid, attestationStatement);
    }

    @Test
    void validate_packed_test() {

        Set<TrustAnchor> trustAnchors = CertificateUtil.generateTrustAnchors(
                Collections.singletonList(TestAttestationUtil.load3tierTestRootCACertificate()));
        when(trustAnchorRepository.find((AAGUID) any())).thenReturn(trustAnchors);

        CertificateBaseAttestationStatement attestationStatement = TestAttestationStatementUtil.createBasicPackedAttestationStatement(TestAttestationUtil.load3tierTestAttestationCertificatePath());
        target.validate(aaguid, attestationStatement);
    }

    @Test
    void validate_with_empty_trustAnchors_test() {

        Set<TrustAnchor> trustAnchors = Collections.emptySet();
        when(trustAnchorRepository.find(aaguid)).thenReturn(trustAnchors);

        CertificateBaseAttestationStatement attestationStatement = TestAttestationStatementUtil.createFIDOU2FAttestationStatement(TestAttestationUtil.load2tierTestAttestationCertificatePath());
        assertThrows(TrustAnchorNotFoundException.class,
                () -> target.validate(aaguid, attestationStatement)
        );
    }

    @Test
    void validate_with_trustAnchor_which_equals_to_x5c() {

        X509Certificate attestationCertificate = TestAttestationUtil.load3tierTestAttestationCertificatePath().getEndEntityAttestationCertificate().getCertificate();
        X509Certificate attestationCertificateLoadedAnotherTime = TestAttestationUtil.load3tierTestAttestationCertificatePath().getEndEntityAttestationCertificate().getCertificate();

        Set<TrustAnchor> trustAnchors = CertificateUtil.generateTrustAnchors(Collections.singletonList(attestationCertificate));
        when(trustAnchorRepository.find((AAGUID) any())).thenReturn(trustAnchors);

        AttestationCertificatePath attestationCertificatePath = new AttestationCertificatePath(attestationCertificateLoadedAnotherTime, Collections.emptyList());
        CertificateBaseAttestationStatement attestationStatement = TestAttestationStatementUtil.createBasicPackedAttestationStatement(attestationCertificatePath);
        target.validate(aaguid, attestationStatement);
    }

    @Test
    void validate_full_chain_test() {

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
                () -> target.validate(aaguid, attestationStatement)
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


}