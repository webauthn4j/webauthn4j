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
import com.webauthn4j.data.jws.JWAIdentifier;
import com.webauthn4j.metadata.data.MetadataBLOB;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class LocalFileMetadataBLOBProviderTest {

    @TempDir
    Path tempDir;

    @Test
    void test() throws IOException {
        Path blobPath = new File("src/test/resources/integration/component/blob.jwt").toPath();
        Path dstPath = tempDir.resolve("blob.jwt");
        Files.copy(blobPath, dstPath);
        LocalFileMetadataBLOBProvider target = new LocalFileMetadataBLOBProvider(new ObjectConverter(), dstPath);
        MetadataBLOB metadataBLOB = target.provide();
        assertThat(metadataBLOB).isNotNull();
        assertThat(metadataBLOB.getHeader().getAlg()).isEqualTo(JWAIdentifier.RS256);
        assertThat(metadataBLOB.getHeader().getX5c()).isNotNull();
        assertThat(metadataBLOB.getSignature()).isNotNull();
        assertThat(metadataBLOB.getPayload()).isNotNull();
        assertThat(metadataBLOB.getPayload().getNo()).isEqualTo(9);
    }

}