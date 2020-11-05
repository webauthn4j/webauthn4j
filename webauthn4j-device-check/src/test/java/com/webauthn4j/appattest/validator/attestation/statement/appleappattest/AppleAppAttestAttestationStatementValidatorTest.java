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

package com.webauthn4j.appattest.validator.attestation.statement.appleappattest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.appattest.converter.jackson.DeviceCheckCBORModule;
import com.webauthn4j.appattest.data.attestation.statement.AppleAppAttestAttestationStatement;
import com.webauthn4j.appattest.validator.DCRegistrationObject;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath;
import com.webauthn4j.test.TestAttestationStatementUtil;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.validator.CoreRegistrationObject;
import com.webauthn4j.validator.exception.BadAttestationStatementException;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class AppleAppAttestAttestationStatementValidatorTest {

    private final AppleAppAttestAttestationStatementValidator target = new AppleAppAttestAttestationStatementValidator();
    private final AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(createObjectConverter());

    @Test
    void validate_test() {
        DCRegistrationObject registrationObject = TestDataUtil.createRegistrationObjectWithAppleAppAttestAttestation();
        target.validate(registrationObject);
    }

    @Test
    void validate_CoreRegistrationObject_test() {
        assertThatThrownBy(() -> {
            target.validate(mock(CoreRegistrationObject.class));
        }).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void supports_CoreRegistrationObject_test() {
        assertThat(target.supports(TestDataUtil.createRegistrationObjectWithPackedAttestation())).isFalse();
    }

    @Test
    void validateX5c_null_test() {
        final AppleAppAttestAttestationStatement appleAppAttestAttestationStatement = new AppleAppAttestAttestationStatement(null, null);
        assertThatThrownBy(() -> {
            target.validateX5c(appleAppAttestAttestationStatement);
        }).isInstanceOf(BadAttestationStatementException.class);
    }

    @Test
    void validateX5c_empty_AttestationCertificatePath_test() {
        final AppleAppAttestAttestationStatement appleAppAttestAttestationStatement = new AppleAppAttestAttestationStatement(new AttestationCertificatePath(), null);
        assertThatThrownBy(() -> {
            target.validateX5c(appleAppAttestAttestationStatement);
        }).isInstanceOf(BadAttestationStatementException.class);
    }

    @Test
    void extractNonce_from_non_AppleAppAttestAttestationCertificate() {
        X509Certificate nonAppleAppAttestAttestationCertificate = TestAttestationStatementUtil.createBasicPackedAttestationStatement().getX5c().getEndEntityAttestationCertificate().getCertificate();
        assertThatThrownBy(() -> {
            target.extractNonce(nonAppleAppAttestAttestationCertificate);
        }).isInstanceOf(BadAttestationStatementException.class);
    }


    private ObjectConverter createObjectConverter() {
        ObjectMapper jsonMapper = new ObjectMapper();
        ObjectMapper cborMapper = new ObjectMapper(new CBORFactory());
        cborMapper.registerModule(new DeviceCheckCBORModule());
        return new ObjectConverter(jsonMapper, cborMapper);
    }


}
