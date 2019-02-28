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

package com.webauthn4j.metadata;

import com.webauthn4j.metadata.data.MetadataItem;
import com.webauthn4j.response.attestation.authenticator.AAGUID;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.assertj.core.api.Java6Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AggregatingMetadataItemsProviderTest {


    @SuppressWarnings("unchecked")
    @Test
    public void provide_test() {
        MetadataItemsProvider<MetadataItem> providerA = mock(MetadataItemsProvider.class);
        Map<AAGUID, Set<MetadataItem>> mapA = new HashMap<>();
        mapA.put(new AAGUID("df495bdc-223a-429d-9f0e-ebfa29155812"), new HashSet<>());
        when(providerA.provide()).thenReturn(mapA);

        MetadataItemsProvider<MetadataItem> providerB = mock(MetadataItemsProvider.class);
        Map<AAGUID, Set<MetadataItem>> mapB = new HashMap<>();
        mapB.put(new AAGUID("d075c221-6a37-4c61-80c7-11254460d5bb"), new HashSet<>());
        when(providerB.provide()).thenReturn(mapB);

        AggregatingMetadataItemsProvider<MetadataItem> target = new AggregatingMetadataItemsProvider<>(Arrays.asList(providerA, providerB));
        assertThat(target.provide()).containsOnlyKeys(new AAGUID("df495bdc-223a-429d-9f0e-ebfa29155812"), new AAGUID("d075c221-6a37-4c61-80c7-11254460d5bb"));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void provide_with_one_of_provider_throws_exception_test() {
        MetadataItemsProvider<MetadataItem> providerA = mock(MetadataItemsProvider.class);
        Map<AAGUID, Set<MetadataItem>> mapA = new HashMap<>();
        mapA.put(new AAGUID("df495bdc-223a-429d-9f0e-ebfa29155812"), new HashSet<>());
        when(providerA.provide()).thenReturn(mapA);

        MetadataItemsProvider<MetadataItem> providerB = mock(MetadataItemsProvider.class);
        when(providerB.provide()).thenThrow(new RuntimeException("unexpected error"));

        AggregatingMetadataItemsProvider<MetadataItem> target = new AggregatingMetadataItemsProvider<>(Arrays.asList(providerA, providerB));
        assertThat(target.provide()).containsOnlyKeys(new AAGUID("df495bdc-223a-429d-9f0e-ebfa29155812"));
    }
}