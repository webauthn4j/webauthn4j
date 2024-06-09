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

package com.webauthn4j.async.metadata.anchor;

import com.webauthn4j.async.anchor.TrustAnchorAsyncRepository;
import com.webauthn4j.data.attestation.authenticator.AAGUID;

import java.security.cert.TrustAnchor;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

public class AggregatingTrustAnchorAsyncRepository implements TrustAnchorAsyncRepository {

    List<TrustAnchorAsyncRepository> repositories;

    public AggregatingTrustAnchorAsyncRepository(TrustAnchorAsyncRepository... repositories) {
        this.repositories = Arrays.asList(repositories);
    }

    @Override
    public CompletionStage<Set<TrustAnchor>> find(AAGUID aaguid) {
        return repositories.stream()
                .map(repository -> repository.find(aaguid))
                .reduce(CompletableFuture.completedFuture(new HashSet<>()), (a, b) -> a.thenCombine(b, (c, d)-> {
                    c.addAll(d);
                    return c;
                }));
    }

    @Override
    public CompletionStage<Set<TrustAnchor>> find(byte[] attestationCertificateKeyIdentifier) {
        return repositories.stream()
                .map(repository -> repository.find(attestationCertificateKeyIdentifier))
                .reduce(CompletableFuture.completedFuture(new HashSet<>()), (a, b) -> a.thenCombine(b, (c, d)-> {
                    c.addAll(d);
                    return c;
                }));
    }
}
