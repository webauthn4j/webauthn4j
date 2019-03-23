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

import com.webauthn4j.anchor.TrustAnchorsProvider;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.data.MetadataItem;

import java.security.cert.TrustAnchor;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class FidoMdsTrustAnchorsProviderAdaptor implements TrustAnchorsProvider {

    private MetadataItemsProvider<MetadataItem> metadataItemMetadataItemsProvider;

    public FidoMdsTrustAnchorsProviderAdaptor(MetadataItemsProvider<MetadataItem> metadataItemMetadataItemsProvider) {
        this.metadataItemMetadataItemsProvider = metadataItemMetadataItemsProvider;
    }

    @Override
    public Map<AAGUID, Set<TrustAnchor>> provide() {
        return metadataItemMetadataItemsProvider.provide().entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        entry -> entry.getValue().stream().flatMap(metadataItem ->
                                metadataItem.getMetadataStatement().getAttestationRootCertificates().stream()
                                        .map(certificate -> new TrustAnchor(certificate, null))
                        ).collect(Collectors.toSet())
                ));
    }
}
