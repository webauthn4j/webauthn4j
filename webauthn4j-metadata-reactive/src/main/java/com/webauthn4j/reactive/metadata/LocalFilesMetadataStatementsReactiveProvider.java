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

package com.webauthn4j.reactive.metadata;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.data.statement.MetadataStatement;
import com.webauthn4j.reactive.util.internal.FileUtil;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.stream.Collectors;

public class LocalFilesMetadataStatementsReactiveProvider implements MetadataStatementsReactiveProvider {

    private final ObjectConverter objectConverter;
    private final Path[] paths;

    public LocalFilesMetadataStatementsReactiveProvider(ObjectConverter objectConverter, Path... paths){
        this.objectConverter = objectConverter;
        this.paths = paths;
    }

    @Override
    public CompletableFuture<List<MetadataStatement>> provide() {
        var completionStages = Arrays.stream(paths)
                .map(FileUtil::load)
                .map(CompletionStage::toCompletableFuture)
                .collect(Collectors.toList());
        CompletableFuture<Void> joinedFuture = CompletableFuture.allOf(completionStages.toArray(CompletableFuture[]::new));
        return joinedFuture
                .thenApply(__ -> completionStages.stream().map(loadedByte -> loadedByte.toCompletableFuture().join()))
                .thenApply(stream -> stream.map(item -> objectConverter.getJsonConverter().readValue(new ByteArrayInputStream(item), MetadataStatement.class)).collect(Collectors.toList()));
    }
}
