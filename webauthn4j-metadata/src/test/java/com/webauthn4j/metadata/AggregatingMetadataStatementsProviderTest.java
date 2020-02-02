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

package com.webauthn4j.metadata;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.data.statement.MetadataStatement;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.assertj.core.api.Java6Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AggregatingMetadataStatementsProviderTest {


    @Test
    void provide_test() {
        MetadataStatementsProvider providerA = mock(MetadataStatementsProvider.class);
        Map<AAGUID, Set<MetadataStatement>> mapA = new HashMap<>();
        mapA.put(new AAGUID("df495bdc-223a-429d-9f0e-ebfa29155812"), new HashSet<>());
        when(providerA.provide()).thenReturn(mapA);

        MetadataStatementsProvider providerB = mock(MetadataStatementsProvider.class);
        Map<AAGUID, Set<MetadataStatement>> mapB = new HashMap<>();
        mapB.put(new AAGUID("d075c221-6a37-4c61-80c7-11254460d5bb"), new HashSet<>());
        when(providerB.provide()).thenReturn(mapB);

        AggregatingMetadataStatementsProvider target = new AggregatingMetadataStatementsProvider(Arrays.asList(providerA, providerB));
        assertThat(target.provide()).containsOnlyKeys(new AAGUID("df495bdc-223a-429d-9f0e-ebfa29155812"), new AAGUID("d075c221-6a37-4c61-80c7-11254460d5bb"));
    }

    @Test
    void provide_with_one_of_provider_throws_exception_test() {
        MetadataStatementsProvider providerA = mock(MetadataStatementsProvider.class);
        Map<AAGUID, Set<MetadataStatement>> mapA = new HashMap<>();
        mapA.put(new AAGUID("df495bdc-223a-429d-9f0e-ebfa29155812"), new HashSet<>());
        when(providerA.provide()).thenReturn(mapA);

        MetadataStatementsProvider providerB = mock(MetadataStatementsProvider.class);
        when(providerB.provide()).thenThrow(new RuntimeException("unexpected error"));

        AggregatingMetadataStatementsProvider target = new AggregatingMetadataStatementsProvider(Arrays.asList(providerA, providerB));
        assertThat(target.provide()).containsOnlyKeys(new AAGUID("df495bdc-223a-429d-9f0e-ebfa29155812"));
    }
}