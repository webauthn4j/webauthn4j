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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class AggregatingMetadataStatementsProvider implements MetadataStatementsProvider {

    private Logger logger = LoggerFactory.getLogger(AggregatingMetadataStatementsProvider.class);

    private List<MetadataStatementsProvider> metadataStatementsProviders;

    public AggregatingMetadataStatementsProvider(List<MetadataStatementsProvider> metadataStatementsProviders) {
        this.metadataStatementsProviders = metadataStatementsProviders;
    }

    @SuppressWarnings("Duplicates")
    @Override
    public Map<AAGUID, Set<MetadataStatement>> provide() {
        return metadataStatementsProviders.stream()
                .flatMap(provider -> {
                    try {
                        return provider.provide().entrySet().stream();
                    } catch (RuntimeException e) {
                        logger.warn("Failed to load metadata from one of metadataStatementsProviders", e);
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }
}
