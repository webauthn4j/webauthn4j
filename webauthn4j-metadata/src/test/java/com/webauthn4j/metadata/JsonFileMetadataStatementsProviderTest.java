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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.converter.jackson.WebAuthnMetadataJSONModule;
import com.webauthn4j.metadata.data.statement.MetadataStatement;
import com.webauthn4j.metadata.exception.UnknownProtocolFamilyException;
import org.junit.jupiter.api.Test;

import java.io.UncheckedIOException;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JsonFileMetadataStatementsProviderTest {

    private JsonConverter jsonConverter;

    public JsonFileMetadataStatementsProviderTest() {
        ObjectMapper jsonMapper = new ObjectMapper();
        jsonMapper.registerModule(new WebAuthnMetadataJSONModule());
        jsonConverter = new JsonConverter(jsonMapper);
    }

    @Test
    void fetchMetadata() throws URISyntaxException {
        List<Path> paths = new ArrayList<>(4);
        paths.add(Paths.get(ClassLoader.getSystemResource("com/webauthn4j/metadata/JsonMetadataItem_fido2.json").toURI()));
        paths.add(Paths.get(ClassLoader.getSystemResource("com/webauthn4j/metadata/JsonMetadataItem_u2f.json").toURI()));
        paths.add(Paths.get(ClassLoader.getSystemResource("com/webauthn4j/metadata/JsonMetadataItem_uaf.json").toURI()));
        JsonFileMetadataStatementsProvider provider = new JsonFileMetadataStatementsProvider(jsonConverter, paths);
        Map<AAGUID, Set<MetadataStatement>> itemMapInFirstCall = provider.provide();
        readMetadataItem(itemMapInFirstCall);
        // read again to run through all branches of JsonFileMetadataStatementsProvider.provider(), and confirm it
        Map<AAGUID, Set<MetadataStatement>> itemMap = provider.provide();
        readMetadataItem(itemMap);
        assertThat(itemMap).isSameAs(itemMapInFirstCall);
    }

    @Test
    void fetchMetadataFromUnknownProtocolFamilyMetadataStatementFile() throws URISyntaxException {
        List<Path> paths = new ArrayList<>(4);
        paths.add(Paths.get(ClassLoader.getSystemResource("com/webauthn4j/metadata/JsonMetadataItem_unknown_protocol.json").toURI()));
        JsonFileMetadataStatementsProvider provider = new JsonFileMetadataStatementsProvider(jsonConverter, paths);
        assertThrows(UnknownProtocolFamilyException.class, provider::provide);
    }


    @Test
    void fetchMetadataFromNonExistentFile() {
        Path path = Paths.get("NonExistentFile.json");
        List<Path> paths = Collections.singletonList(path);
        JsonFileMetadataStatementsProvider provider = new JsonFileMetadataStatementsProvider(jsonConverter, paths);
        assertThrows(UncheckedIOException.class, provider::provide);
    }

    private void readMetadataItem(Map<AAGUID, Set<MetadataStatement>> itemMap) {
        itemMap.keySet().stream()
                .flatMap(key -> itemMap.get(key).stream())
                .forEach(item -> assertThat(item.getDescription()).isNotNull());
    }
}
