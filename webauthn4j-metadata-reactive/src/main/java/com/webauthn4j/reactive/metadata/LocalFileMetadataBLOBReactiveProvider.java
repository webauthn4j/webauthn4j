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
import com.webauthn4j.metadata.CachingMetadataBLOBProvider;
import com.webauthn4j.metadata.data.MetadataBLOB;
import com.webauthn4j.metadata.data.MetadataBLOBFactory;
import com.webauthn4j.reactive.util.internal.FileUtil;
import org.jetbrains.annotations.NotNull;

import javax.annotation.processing.Completion;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CompletionStage;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Load MetadataBLOB from a local file. This provider doesn't validate MetadataBLOB signature as it trusts local metadata BLOB file.
 */
public class LocalFileMetadataBLOBReactiveProvider extends CachingMetadataBLOBReactiveProvider {

    private final MetadataBLOBFactory metadataBLOBFactory;
    private final Path path;

    public LocalFileMetadataBLOBReactiveProvider(@NotNull ObjectConverter objectConverter, @NotNull Path path) {
        this.metadataBLOBFactory = new MetadataBLOBFactory(objectConverter);
        this.path = path;
    }

    protected @NotNull CompletionStage<MetadataBLOB> doProvide(){
        return FileUtil.load(path).thenApply( bytes -> metadataBLOBFactory.parse(new String(bytes)));
    }
}
