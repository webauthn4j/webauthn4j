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

import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.data.statement.MetadataStatement;
import com.webauthn4j.metadata.validator.MetadataStatementValidator;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

public class JsonFileMetadataStatementsProvider implements MetadataStatementsProvider {

    private final JsonConverter jsonConverter;
    private final MetadataStatementValidator metadataStatementValidator = new MetadataStatementValidator();
    private final List<Path> paths;
    private Map<AAGUID, Set<MetadataStatement>> cachedMetadataItems;

    public JsonFileMetadataStatementsProvider(ObjectConverter objectConverter, List<Path> paths) {
        this.jsonConverter = objectConverter.getJsonConverter();
        this.paths = paths;
    }

    @Override
    public Map<AAGUID, Set<MetadataStatement>> provide() {
        if (cachedMetadataItems == null) {
            cachedMetadataItems =
                    paths.stream()
                            .map(this::readJsonFile)
                            .distinct()
                            .collect(Collectors.groupingBy(this::extractAAGUID))
                            .entrySet().stream()
                            .collect(Collectors.toMap(Map.Entry::getKey, entry -> new HashSet<>(entry.getValue())));

        }
        return cachedMetadataItems;
    }

    private AAGUID extractAAGUID(MetadataStatement metadataStatement) {
        switch (metadataStatement.getProtocolFamily()) {
            case "fido2":
                return metadataStatement.getAaguid();
            case "u2f":
                return AAGUID.ZERO;
            case "uaf":
            default:
                return AAGUID.NULL;
        }
    }

    MetadataStatement readJsonFile(Path path) {
        try (InputStream inputStream = Files.newInputStream(path)) {
            MetadataStatement metadataStatement = jsonConverter.readValue(inputStream, MetadataStatement.class);
            metadataStatementValidator.validate(metadataStatement);
            return metadataStatement;
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to load a metadata statement json file", e);
        }
    }
}
