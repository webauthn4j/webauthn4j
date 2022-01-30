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

package com.webauthn4j.metadata.data;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.jws.JWSHeader;
import com.webauthn4j.metadata.LocalFileMetadataBLOBProvider;
import com.webauthn4j.util.Base64UrlUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class MetadataBLOBTest {

    @TempDir
    Path tempDir;

    @Test
    void test(){
        MetadataBLOB metadataBLOB = getMetadataBLOB();
        assertThat(metadataBLOB).isNotNull();
        JWSHeader header = metadataBLOB.getHeader();
        MetadataBLOBPayload payload = metadataBLOB.getPayload();
        assertThat(header).isNotNull();
        assertThat(payload).isNotNull();
        assertThat(payload.getNo()).isEqualTo(9);
        assertThat(payload.getEntries()).hasSize(98);
        assertThat(payload.getLegalHeader()).isNotEmpty();
        assertThat(payload.getNextUpdate()).isEqualTo("2021-12-01");
        assertThat(metadataBLOB.getSignature()).isEqualTo(Base64UrlUtil.decode("CLHevWeNEwJynHqxs5-xH0wlOuhz3cu9r8UL4fyJ0T7Avbi-OdE2LnT2ZUDjJC0F8R1V6bmrUBoyR4bjTTCt5FpKNyOwfSEVf3ToK6ZR3kITEDGfJgztDxn8rjS26FpM0JHnVms9-_74AEqVas7qVoPoKq9HYQyHUkvWdeVHhziOEMIa6NYEJa7qhtzlKi8ZKTJeEYbjUWVIhgTOHNUi_jGfLFTm10HDgiFc6pa5M5-BvoOKBCztzW_tzCl96wP8K2ujVg0xHA-RRTwinGAbDiwSIDGpYymhElQ40gdpsHtRYPOPQiqZgQX7u_CRGN2CA6qykF9mOY2U2RhA3cxZpw"));
    }

    private MetadataBLOB getMetadataBLOB() {
        try {
            Path blobPath = new File("src/test/resources/integration/component/blob.jwt").toPath();
            Path dstPath = tempDir.resolve("blob.jwt");
            Files.copy(blobPath, dstPath);
            LocalFileMetadataBLOBProvider target = new LocalFileMetadataBLOBProvider(new ObjectConverter(), dstPath);
            return target.provide();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

}