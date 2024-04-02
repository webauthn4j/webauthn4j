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

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.validator.attestation.statement.androidkey.NullAndroidKeyAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.androidsafetynet.NullAndroidSafetyNetAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.none.NoneAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.packed.NullPackedAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.tpm.NullTPMAttestationStatementValidator;
import com.webauthn4j.validator.attestation.statement.u2f.NullFIDOU2FAttestationStatementValidator;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.NullCertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.exception.*;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

class RegistrationDataValidatorTest {

    private final RegistrationDataValidator target;

    public RegistrationDataValidatorTest() {
        ObjectConverter objectConverter = new ObjectConverter();

        target = new RegistrationDataValidator(Arrays.asList(
                new NoneAttestationStatementValidator(),
                new NullFIDOU2FAttestationStatementValidator(),
                new NullPackedAttestationStatementValidator(),
                new NullTPMAttestationStatementValidator(),
                new NullAndroidKeyAttestationStatementValidator(),
                new NullAndroidSafetyNetAttestationStatementValidator()
        ),
                new NullCertPathTrustworthinessValidator(),
                new NullSelfAttestationTrustworthinessValidator(),
                new ArrayList<>(),
                objectConverter);
    }

    @Test
    void validateAlg_test(){
        List<PublicKeyCredentialParameters> pubKeyCredParams = Arrays.asList(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256), new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256));
        target.validateAlg(COSEAlgorithmIdentifier.ES256, pubKeyCredParams);
    }

    @Test
    void validateAlg_not_allowed_alg_test(){
        List<PublicKeyCredentialParameters> pubKeyCredParams = Collections.singletonList(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256));
        assertThrows(NotAllowedAlgorithmException.class,
                () -> target.validateAlg(COSEAlgorithmIdentifier.ES256, pubKeyCredParams)
        );
    }

    @Test
    void validateAuthenticatorDataField_test() {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], (byte) 0, 0);
        assertThrows(ConstraintViolationException.class,
                () -> target.validateAuthenticatorDataField(authenticatorData)
        );
    }

    @Test
    void validateUVUPFlags_not_required_test() {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], (byte) 0, 0);
        target.validateUVUPFlags(authenticatorData, false, false);
    }

    @Test
    void validateUVUPFlags_required_test() {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], (byte) (AuthenticatorData.BIT_UP | AuthenticatorData.BIT_UV), 0);
        target.validateUVUPFlags(authenticatorData, true, true);
    }

    @Test
    void validateUVUPFlags_UserNotVerifiedException_test() {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], (byte) 0, 0);
        assertThrows(UserNotVerifiedException.class,
                () -> target.validateUVUPFlags(authenticatorData, true, false)
        );
    }

    @Test
    void validateUVUPFlags_UserNotPresentException_test() {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], (byte) 0, 0);
        assertThrows(UserNotPresentException.class,
                () -> target.validateUVUPFlags(authenticatorData, false, true)
        );
    }

    @Test
    void validateBEBSFlags_only_BSFlag_set_test() {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], AuthenticatorData.BIT_BS, 0);
        assertThrows(IllegalBackupStateException.class,
                () -> target.validateBEBSFlags(authenticatorData)
        );
    }

    @Test
    void validateCredentialIdLength_too_long_credentialId_test(){
        assertThrows(CredentialIdTooLongException.class,
                () -> target.validateCredentialIdLength(new byte[1024])
        );
    }

    @Test
    void getCustomRegistrationValidators() {
        CustomRegistrationValidator customRegistrationValidator = mock(CustomRegistrationValidator.class);
        target.getCustomRegistrationValidators().add(customRegistrationValidator);
        assertThat(target.getCustomRegistrationValidators()).contains(customRegistrationValidator);
    }

    @Test
    void getter_setter_test() {
        target.setOriginValidator(new TestOriginValidator());
        assertThat(target.getOriginValidator()).isInstanceOf(TestOriginValidator.class);
    }

    private static class TestOriginValidator extends OriginValidatorImpl {
    }
}
