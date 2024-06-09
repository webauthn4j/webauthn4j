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
import com.webauthn4j.util.HexUtil;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.nio.file.Path;
import java.security.cert.TrustAnchor;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class MetadataStatementsBasedTrustAnchorRepositoryTest {

    @Test
    void find_by_attestationCertificateKeyIdentifier_test(){
        Path jsonFilePath = new File("src/test/resources/com/webauthn4j/metadata/JsonMetadataItem_u2f.json").toPath();
        MetadataStatementsBasedTrustAnchorRepository repository = new MetadataStatementsBasedTrustAnchorRepository(new ObjectConverter(), jsonFilePath);
        Set<TrustAnchor> trustAnchors = repository.find(HexUtil.decode("7c0903708b87115b0b422def3138c3c864e44573"));
        assertThat(trustAnchors).hasSize(1);
    }

    @Test
    void find_by_aaguid_test(){
        Path jsonFilePath = new File("src/test/resources/com/webauthn4j/metadata/JsonMetadataItem_fido2.json").toPath();
        MetadataStatementsBasedTrustAnchorRepository repository = new MetadataStatementsBasedTrustAnchorRepository(new ObjectConverter(), jsonFilePath);
        Set<TrustAnchor> trustAnchors = repository.find(new AAGUID("0132d110-bf4e-4208-a403-ab4f5f12efe5"));
        assertThat(trustAnchors).hasSize(1);
    }

}