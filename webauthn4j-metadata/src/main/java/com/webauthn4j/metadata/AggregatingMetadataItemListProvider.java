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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public class AggregatingMetadataItemListProvider<T extends MetadataItem> implements MetadataItemListProvider<T>{

    transient Logger logger = LoggerFactory.getLogger(AggregatingMetadataItemListProvider.class);


    private List<MetadataItemListProvider<T>> metadataItemListProviders;

    public AggregatingMetadataItemListProvider(List<MetadataItemListProvider<T>> metadataItemListProviders) {
        this.metadataItemListProviders = metadataItemListProviders;
    }

    @Override
    public Map<AAGUID, List<T>> provide() {
        return metadataItemListProviders.stream()
                .flatMap(provider -> {
                    try{
                        return provider.provide().entrySet().stream();
                    }
                    catch (RuntimeException e){
                        logger.warn("Failed to load metadata from one of metadataItemListProviders", e);
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }
}
