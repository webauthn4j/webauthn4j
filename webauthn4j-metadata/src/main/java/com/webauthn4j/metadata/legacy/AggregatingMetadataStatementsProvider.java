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
import com.webauthn4j.metadata.legacy.data.statement.MetadataStatement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class AggregatingMetadataStatementsProvider implements MetadataStatementsProvider {

    private final Logger logger = LoggerFactory.getLogger(AggregatingMetadataStatementsProvider.class);

    private final List<MetadataStatementsProvider> metadataStatementsProviders;

    public AggregatingMetadataStatementsProvider(List<MetadataStatementsProvider> metadataStatementsProviders) {
        this.metadataStatementsProviders = metadataStatementsProviders;
    }

    @Override
    public Map<AAGUID, Set<MetadataStatement>> provide() {
        Map<AAGUID, Set<MetadataStatement>> map = new HashMap<>();
        metadataStatementsProviders.forEach(provider -> {
            try {
                Map<AAGUID, Set<MetadataStatement>> provided = provider.provide();
                provided.keySet().forEach(aaguid -> {
                    map.putIfAbsent(aaguid, new HashSet<>());
                    map.get(aaguid).addAll(provided.get(aaguid));
                });
            } catch (RuntimeException e) {
                logger.warn("Failed to load metadata from one of metadataStatementsProviders", e);
            }
        });
        return map;
    }
}
