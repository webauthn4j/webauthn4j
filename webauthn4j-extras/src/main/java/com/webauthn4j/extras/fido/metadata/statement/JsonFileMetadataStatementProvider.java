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

import com.webauthn4j.registry.Registry;
import com.webauthn4j.util.UUIDUtil;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

public class JsonFileMetadataStatementProvider implements MetadataStatementProvider {

    private Registry registry;
    private List<Path> paths = Collections.emptyList();
    private Map<UUID, List<MetadataStatement>> cachedMetadataStatements;

    public JsonFileMetadataStatementProvider(Registry registry) {
        this.registry = registry;
    }

    @Override
    public Map<UUID, List<MetadataStatement>> provide() {
        if(cachedMetadataStatements == null){
            cachedMetadataStatements = paths.stream()
                    .map(this::readJsonFile)
                    .collect(Collectors.groupingBy(item -> UUIDUtil.fromString(item.getAaguid())));
        }
        return cachedMetadataStatements;
    }

    MetadataStatement readJsonFile(Path path){
        try(InputStream inputStream = Files.newInputStream(path)){
            return registry.getJsonMapper().readValue(inputStream, MetadataStatement.class);
        }catch (IOException e) {
            throw new UncheckedIOException("Failed to load a metadata statement json file", e);
        }
    }
}
