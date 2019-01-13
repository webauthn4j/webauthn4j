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

import java.nio.ByteBuffer;
import java.security.cert.TrustAnchor;
import java.util.*;
import java.util.stream.Collectors;

public class MetadataStatementTrustAnchorProvider implements TrustAnchorProvider {

    private MetadataStatementProvider metadataStatementProvider;

    public MetadataStatementTrustAnchorProvider(MetadataStatementProvider metadataStatementProvider) {
        this.metadataStatementProvider = metadataStatementProvider;
    }

    @Override
    public Map<byte[], Set<TrustAnchor>> provide() {
        List<MetadataStatement> metadataStatements = metadataStatementProvider.provide();

        Map<byte[], Set<TrustAnchor>> result = new HashMap<>();
        metadataStatements.forEach(metadataStatement -> {
            String aaguidStr = metadataStatement.getAaguid();
            byte[] aaguid = aaguidStr == null ? null : convertUUID2Bytes(UUID.fromString(aaguidStr));
            Set<TrustAnchor> set = result.computeIfAbsent(aaguid, k -> new HashSet<>());
            Set<TrustAnchor> trustAnchors =
                    metadataStatement.getAttestationRootCertificates().stream()
                            .map(x509Certificate -> new TrustAnchor(x509Certificate, null))
                            .collect(Collectors.toSet());
            set.addAll(trustAnchors);
        });
        return result;
    }

    private static byte[] convertUUID2Bytes(UUID uuid) {
        long hi = uuid.getMostSignificantBits();
        long lo = uuid.getLeastSignificantBits();
        return ByteBuffer.allocate(16).putLong(hi).putLong(lo).array();
    }
}
