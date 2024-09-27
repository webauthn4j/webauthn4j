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
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.util.HexUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class MetadataBLOBBasedMetadataStatementRepositoryTest {

    @TempDir
    Path tempDir;

    @Test
    void find_by_aaguid_test() throws IOException {
        AAGUID aaguid = new AAGUID("9c835346-796b-4c27-8898-d6032f515cc5");
        Path blobPath = new File("src/test/resources/integration/component/blob.jwt").toPath();
        Path dstPath = tempDir.resolve("blob.jwt");
        Files.copy(blobPath, dstPath);
        LocalFileMetadataBLOBProvider metadataBLOBProvider = new LocalFileMetadataBLOBProvider(new ObjectConverter(), dstPath);
        MetadataBLOBBasedMetadataStatementRepository target = new MetadataBLOBBasedMetadataStatementRepository(metadataBLOBProvider);
        assertThat(target.find(aaguid)).hasSize(1);
    }

    @Test
    void find_by_attestationCertificateKeyIdentifier_test() throws IOException {
        byte[] attestationCertificateKeyIdentifier = HexUtil.decode("1434d2f277fe479c35ddf6aa4d08a07cbce99dd7");
        Path blobPath = new File("src/test/resources/integration/component/blob.jwt").toPath();
        Path dstPath = tempDir.resolve("blob.jwt");
        Files.copy(blobPath, dstPath);
        LocalFileMetadataBLOBProvider metadataBLOBProvider = new LocalFileMetadataBLOBProvider(new ObjectConverter(), dstPath);
        MetadataBLOBBasedMetadataStatementRepository target = new MetadataBLOBBasedMetadataStatementRepository(metadataBLOBProvider);
        assertThat(target.find(attestationCertificateKeyIdentifier)).hasSize(1);
    }

    @Test
    void notFidoCertifiedAllowed_test() throws IOException {
        AAGUID aaguid = new AAGUID("3789da91-f943-46bc-95c3-50ea2012f03a");
        Path blobPath = new File("src/test/resources/integration/component/blob.jwt").toPath();
        Path dstPath = tempDir.resolve("blob.jwt");
        Files.copy(blobPath, dstPath);
        LocalFileMetadataBLOBProvider metadataBLOBProvider = new LocalFileMetadataBLOBProvider(new ObjectConverter(), dstPath);
        MetadataBLOBBasedMetadataStatementRepository target = new MetadataBLOBBasedMetadataStatementRepository(metadataBLOBProvider);
        target.setNotFidoCertifiedAllowed(false);
        assertThat(target.isNotFidoCertifiedAllowed()).isFalse();
        assertThat(target.find(aaguid)).isEmpty();
        target.setNotFidoCertifiedAllowed(true);
        assertThat(target.find(aaguid)).hasSize(1);
        assertThat(target.isNotFidoCertifiedAllowed()).isTrue();
    }

    @Test
    void selfAssertionSubmittedAllowed_test() throws IOException {
        AAGUID aaguid = new AAGUID("01d993d9-33d7-4db5-a7a9-7edc56ddfdb5");
        Path blobPath = new File("src/test/resources/integration/component/test-blob.jwt").toPath();
        Path dstPath = tempDir.resolve("blob.jwt");
        Files.copy(blobPath, dstPath);
        LocalFileMetadataBLOBProvider metadataBLOBProvider = new LocalFileMetadataBLOBProvider(new ObjectConverter(), dstPath);
        MetadataBLOBBasedMetadataStatementRepository target = new MetadataBLOBBasedMetadataStatementRepository(metadataBLOBProvider);

        target.setSelfAssertionSubmittedAllowed(false);
        assertThat(target.isSelfAssertionSubmittedAllowed()).isFalse();
        assertThat(target.find(aaguid)).isEmpty();

        target.setSelfAssertionSubmittedAllowed(true);
        assertThat(target.find(aaguid)).hasSize(1);
        assertThat(target.isSelfAssertionSubmittedAllowed()).isTrue();
    }
}