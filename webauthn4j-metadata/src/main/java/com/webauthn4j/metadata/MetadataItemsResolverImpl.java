/*
 * Copyright 2018 the original author or authors.
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

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.data.MetadataItem;
import com.webauthn4j.util.AssertUtil;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class MetadataItemsResolverImpl implements MetadataItemsResolver {

    private MetadataItemsProvider metadataItemsProvider;

    public MetadataItemsResolverImpl(MetadataItemsProvider metadataItemsProvider) {
        this.metadataItemsProvider = metadataItemsProvider;
    }

    @Override
    public Set<MetadataItem> resolve(AAGUID aaguid) {
        AssertUtil.notNull(aaguid, "aaguid must not be null");

        Map<AAGUID, Set<MetadataItem>> metadataItemMap = metadataItemsProvider.provide();

        HashSet<MetadataItem> list = new HashSet<>();
        list.addAll(metadataItemMap.getOrDefault(AAGUID.NULL, Collections.emptySet()));
        list.addAll(metadataItemMap.getOrDefault(aaguid, Collections.emptySet()));
        return list;
    }
}
