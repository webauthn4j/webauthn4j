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

package com.webauthn4j.metadata.legacy;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.legacy.data.MetadataItem;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AggregatingMetadataItemsProviderTest {

    @Test
    void provide_test_common_entry_returned_from_providers() {

        MetadataItem metadataItemA = mock(MetadataItem.class);
        MetadataItem metadataItemB = mock(MetadataItem.class);

        MetadataItemsProvider providerA = mock(MetadataItemsProvider.class);
        Map<AAGUID, Set<MetadataItem>> mapA = new HashMap<>();
        mapA.put(new AAGUID("df495bdc-223a-429d-9f0e-ebfa29155812"), new HashSet<>(Collections.singletonList(metadataItemA)));
        when(providerA.provide()).thenReturn(mapA);

        MetadataItemsProvider providerB = mock(MetadataItemsProvider.class);
        Map<AAGUID, Set<MetadataItem>> mapB = new HashMap<>();
        mapB.put(new AAGUID("df495bdc-223a-429d-9f0e-ebfa29155812"), new HashSet<>(Arrays.asList(metadataItemA, metadataItemB)));
        when(providerB.provide()).thenReturn(mapB);

        MetadataItemsProvider target = new AggregatingMetadataItemsProvider(Arrays.asList(providerA, providerB));
        assertThat(target.provide().keySet()).containsExactly(new AAGUID("df495bdc-223a-429d-9f0e-ebfa29155812"));
        assertThat(target.provide().get(new AAGUID("df495bdc-223a-429d-9f0e-ebfa29155812"))).containsExactlyInAnyOrder(metadataItemA, metadataItemB);
    }

}