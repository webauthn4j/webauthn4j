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

import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.assertj.core.api.Assertions.assertThat;

import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.metadata.data.MetadataItem;
import com.webauthn4j.response.attestation.authenticator.AAGUID;

class JsonFileMetadataItemsProviderTest {

    private JsonConverter jsonConverter = new JsonConverter();

    @Test
    void fetchMetadata() throws Exception {
       List<Path> paths= new ArrayList<>(4);
       paths.add(Paths.get(ClassLoader.getSystemResource("com/webauthn4j/metadata/JsonMetadataItem_fido2.json").toURI()));
       paths.add(Paths.get(ClassLoader.getSystemResource("com/webauthn4j/metadata/JsonMetadataItem_u2f.json").toURI()));
       paths.add(Paths.get(ClassLoader.getSystemResource("com/webauthn4j/metadata/JsonMetadataItem_uaf.json").toURI()));
       paths.add(Paths.get(ClassLoader.getSystemResource("com/webauthn4j/metadata/JsonMetadataItem_unknown_protocol.json").toURI()));
       JsonFileMetadataItemsProvider provider = new JsonFileMetadataItemsProvider(jsonConverter, paths);
       Map<AAGUID, Set<MetadataItem>> itemMapInFirstCall = provider.provide();
       readMetadataItem(itemMapInFirstCall);
       // read again to run through all branches of JsonFileMetadataItemsProvider.provider(), and confirm it
       Map<AAGUID, Set<MetadataItem>> itemMap = provider.provide();
       readMetadataItem(itemMap);
       assertThat(itemMap).isEqualTo(itemMapInFirstCall);
    }

    @Test
    void fetchMetadataFromNonExistentFile() throws Exception {
       Path path = Paths.get("NonExistentFile.json");
       List<Path> paths = Collections.singletonList(path);
       JsonFileMetadataItemsProvider provider = new JsonFileMetadataItemsProvider(jsonConverter, paths);
       assertThrows(UncheckedIOException.class, () -> provider.provide());
    }

    private void readMetadataItem(Map<AAGUID, Set<MetadataItem>> itemMap) {
        itemMap.keySet().stream()
                .flatMap(key -> itemMap.get(key).stream())
                .forEach(item -> assertThat(item.getMetadataStatement().getDescription()).isNotNull());
    }
}
