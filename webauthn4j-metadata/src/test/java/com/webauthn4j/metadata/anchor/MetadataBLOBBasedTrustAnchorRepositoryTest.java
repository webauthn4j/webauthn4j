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

package com.webauthn4j.metadata.anchor;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.LocalFileMetadataBLOBProvider;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.util.HexUtil;
import com.webauthn4j.verifier.RegistrationObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.TrustAnchor;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class MetadataBLOBBasedTrustAnchorRepositoryTest {

    @TempDir
    Path tempDir;

    @Test
    void find_by_aaguid_test(){
        MetadataBLOBBasedTrustAnchorRepository target = createWithBlob("src/test/resources/integration/component/blob.jwt");
        Set<TrustAnchor> trustAnchors = target.find(new AAGUID("08987058-CADC-4B81-B6E1-30DE50DCBE96"));
        assertThat(trustAnchors).isNotEmpty();
    }

    @Test
    void find_by_attestationCertificateIdentifier_test(){
        MetadataBLOBBasedTrustAnchorRepository target = createWithBlob("src/test/resources/integration/component/blob.jwt");
        Set<TrustAnchor> trustAnchors = target.find(HexUtil.decode("2fea8f357c7a54a57f45cda72fafb34d1d449fd4"));
        assertThat(trustAnchors).isNotEmpty();
    }

    @Test
    void validate_test() {
        MetadataBLOBBasedTrustAnchorRepository target = createWithBlob("src/test/resources/integration/component/blob.jwt");
        RegistrationObject registrationObject = TestDataUtil.createRegistrationObjectWithTPMAttestation();
        @SuppressWarnings("ConstantConditions")
        AAGUID aaguid = registrationObject.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getAaguid();
        assertThat(target.find(aaguid)).isNotEmpty();
    }

    @Test
    void setNotFidoCertifiedAllowed_test(){
        Set<TrustAnchor> trustAnchors;

        MetadataBLOBBasedTrustAnchorRepository target = createWithBlob("src/test/resources/integration/component/test-blob.jwt");

        target.setNotFidoCertifiedAllowed(false);
        trustAnchors = target.find(new AAGUID("d54e9697-08ca-4d95-b2c2-ef9dd7c7d105"));
        assertThat(trustAnchors).isEmpty();
        assertThat(target.isNotFidoCertifiedAllowed()).isFalse();

        target.setNotFidoCertifiedAllowed(true);
        trustAnchors = target.find(new AAGUID("d54e9697-08ca-4d95-b2c2-ef9dd7c7d105"));
        assertThat(trustAnchors).isNotEmpty();
        assertThat(target.isNotFidoCertifiedAllowed()).isTrue();
    }

    @Test
    void setSelfAssertionSubmittedAllowed_test(){
        Set<TrustAnchor> trustAnchors;

        MetadataBLOBBasedTrustAnchorRepository target = createWithBlob("src/test/resources/integration/component/test-blob.jwt");

        target.setSelfAssertionSubmittedAllowed(false);
        trustAnchors = target.find(new AAGUID("60a94677-44e9-4594-a94e-cf44effd8b9a"));
        assertThat(trustAnchors).isEmpty();
        assertThat(target.isSelfAssertionSubmittedAllowed()).isFalse();

        target.setSelfAssertionSubmittedAllowed(true);
        trustAnchors = target.find(new AAGUID("60a94677-44e9-4594-a94e-cf44effd8b9a"));
        assertThat(trustAnchors).isNotEmpty();
        assertThat(target.isSelfAssertionSubmittedAllowed()).isTrue();
    }

    private MetadataBLOBBasedTrustAnchorRepository createWithBlob(String filePath){
        try {
            Path blobPath = new File(filePath).toPath();
            Path dstPath = tempDir.resolve("blob.jwt");
            Files.copy(blobPath, dstPath);
            LocalFileMetadataBLOBProvider localFileMetadataBLOBProvider = new LocalFileMetadataBLOBProvider(new ObjectConverter(), dstPath);
            return new MetadataBLOBBasedTrustAnchorRepository(localFileMetadataBLOBProvider);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }


}