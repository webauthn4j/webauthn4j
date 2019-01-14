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

package com.webauthn4j.extras.fido.metadata.statement;

import com.webauthn4j.anchor.TrustAnchorProvider;

import java.security.cert.TrustAnchor;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class MetadataStatementTrustAnchorProvider implements TrustAnchorProvider {

    private MetadataStatementProvider metadataStatementProvider;

    public MetadataStatementTrustAnchorProvider(MetadataStatementProvider metadataStatementProvider) {
        this.metadataStatementProvider = metadataStatementProvider;
    }

    @Override
    public Map<byte[], Set<TrustAnchor>> provide() {
        Map<byte[], List<MetadataStatement>> metadataStatements = metadataStatementProvider.provide();

        return metadataStatements.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, item -> item.getValue().stream().flatMap(this::extractTrustAnchors).collect(Collectors.toSet())));

    }

    private Stream<TrustAnchor> extractTrustAnchors(MetadataStatement metadataStatement){
        return metadataStatement.getAttestationRootCertificates().stream()
                .map(certificate -> new TrustAnchor(certificate, null));
    }

}
