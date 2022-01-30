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

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.data.statement.MetadataStatement;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class LocalFilesMetadataStatementsProvider implements MetadataStatementsProvider {

    private final ObjectConverter objectConverter;
    private final Path[] paths;

    public LocalFilesMetadataStatementsProvider(ObjectConverter objectConverter, Path... paths){
        this.objectConverter = objectConverter;
        this.paths = paths;
    }

    @Override
    public @NonNull List<MetadataStatement> provide() {
        return Arrays.stream(paths).map(path ->{
            try (InputStream inputStream = Files.newInputStream(path)) {
                return objectConverter.getJsonConverter().readValue(inputStream, MetadataStatement.class);
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to load a MetadataStatements file", e);
            }
        }).collect(Collectors.toList());
    }
}
