/*
 * Copyright 2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.webauthn4j.validator;

import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.validator.attestation.statement.u2f.FIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.NullCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.exception.BadAaguidException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AttestationValidatorTest {

    @Test
    void validateAAGUID(@Mock(answer = Answers.RETURNS_DEEP_STUBS) AuthenticatorData<RegistrationExtensionAuthenticatorOutput<?>> authenticatorData) {
        AttestationValidator attestationValidator = new AttestationValidator(
                Collections.singletonList(new FIDOU2FAttestationStatementValidator()),
                new NullCertPathTrustworthinessValidator(),
                new NullSelfAttestationTrustworthinessValidator());

        AttestationObject attestationObject = mock(AttestationObject.class);
        when(attestationObject.getFormat()).thenReturn(FIDOU2FAttestationStatement.FORMAT);
        when(authenticatorData.getAttestedCredentialData().getAaguid()).thenReturn(new AAGUID("fea37a71-08ce-479f-bf4b-472a93e2d17d"));
        when(attestationObject.getAuthenticatorData()).thenReturn(authenticatorData);
        assertThrows(BadAaguidException.class,
                () -> attestationValidator.validateAAGUID(attestationObject)
        );
    }
}