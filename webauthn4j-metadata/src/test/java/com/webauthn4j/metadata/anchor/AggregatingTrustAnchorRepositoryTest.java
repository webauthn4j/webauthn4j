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

package com.webauthn4j.metadata.anchor;

import com.webauthn4j.anchor.TrustAnchorRepository;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import org.junit.jupiter.api.Test;

import java.security.cert.TrustAnchor;
import java.util.Collections;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AggregatingTrustAnchorRepositoryTest {

    @Test
    void find_by_aaguid_test(){
        AAGUID aaguid = new AAGUID(UUID.randomUUID());
        TrustAnchor trustAnchorA = mock(TrustAnchor.class);
        TrustAnchor trustAnchorB = mock(TrustAnchor.class);
        TrustAnchorRepository mockA = mock(TrustAnchorRepository.class);
        TrustAnchorRepository mockB = mock(TrustAnchorRepository.class);
        when(mockA.find(aaguid)).thenReturn(Collections.singleton(trustAnchorA));
        when(mockB.find(aaguid)).thenReturn(Collections.singleton(trustAnchorB));
        TrustAnchorRepository target = new AggregatingTrustAnchorRepository(mockA, mockB);
        assertThat(target.find(aaguid)).containsExactlyInAnyOrder(trustAnchorA, trustAnchorB);
    }

    @Test
    void find_by_attestationCertificateKeyIdentifier_test(){
        byte[] attestationCertificateKeyIdentifier = new byte[32];
        TrustAnchor trustAnchorA = mock(TrustAnchor.class);
        TrustAnchor trustAnchorB = mock(TrustAnchor.class);
        TrustAnchorRepository mockA = mock(TrustAnchorRepository.class);
        TrustAnchorRepository mockB = mock(TrustAnchorRepository.class);
        when(mockA.find(attestationCertificateKeyIdentifier)).thenReturn(Collections.singleton(trustAnchorA));
        when(mockB.find(attestationCertificateKeyIdentifier)).thenReturn(Collections.singleton(trustAnchorB));
        TrustAnchorRepository target = new AggregatingTrustAnchorRepository(mockA, mockB);
        assertThat(target.find(attestationCertificateKeyIdentifier)).containsExactlyInAnyOrder(trustAnchorA, trustAnchorB);
    }

}