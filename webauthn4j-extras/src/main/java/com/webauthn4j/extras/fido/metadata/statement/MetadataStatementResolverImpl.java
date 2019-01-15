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

import com.webauthn4j.response.attestation.authenticator.AAGUID;
import com.webauthn4j.util.AssertUtil;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class MetadataStatementResolverImpl implements MetadataStatementResolver {

    private MetadataStatementProvider metadataStatementProvider;

    public MetadataStatementResolverImpl(MetadataStatementProvider metadataStatementProvider) {
        this.metadataStatementProvider = metadataStatementProvider;
    }

    @Override
    public List<MetadataStatement> resolve(AAGUID aaguid) {
        AssertUtil.notNull(aaguid, "aaguid must not be null");

        Map<AAGUID, List<MetadataStatement>> metadataStatements = metadataStatementProvider.provide();

        ArrayList<MetadataStatement> list = new ArrayList<>();
        list.addAll(metadataStatements.getOrDefault(AAGUID.NULL, Collections.emptyList()));
        list.addAll(metadataStatements.getOrDefault(aaguid, Collections.emptyList()));
        return list;
    }
}
