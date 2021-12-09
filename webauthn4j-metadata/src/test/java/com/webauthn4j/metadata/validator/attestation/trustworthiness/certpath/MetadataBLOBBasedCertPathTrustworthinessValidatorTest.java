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

package com.webauthn4j.metadata.validator.attestation.trustworthiness.certpath;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.metadata.LocalFileMetadataBLOBProvider;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.validator.RegistrationObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

class MetadataBLOBBasedCertPathTrustworthinessValidatorTest {

    @TempDir
    Path tempDir;

    @Test
    void validate_test() throws IOException {
        Path blobPath = new File("src/test/resources/integration/component/blob.jwt").toPath();
        Path dstPath = tempDir.resolve("blob.jwt");
        Files.copy(blobPath, dstPath);
        LocalFileMetadataBLOBProvider localFileMetadataBLOBProvider = new LocalFileMetadataBLOBProvider(dstPath, new ObjectConverter());
        MetadataBLOBBasedCertPathTrustworthinessValidator target = new MetadataBLOBBasedCertPathTrustworthinessValidator(localFileMetadataBLOBProvider);
        RegistrationObject registrationObject = TestDataUtil.createRegistrationObjectWithTPMAttestation();
        AAGUID aaguid = registrationObject.getAttestationObject().getAuthenticatorData().getAttestedCredentialData().getAaguid();
        target.validate(aaguid, (CertificateBaseAttestationStatement) registrationObject.getAttestationObject().getAttestationStatement());
    }
}