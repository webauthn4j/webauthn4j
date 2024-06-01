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

package com.webauthn4j.verifier;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.verifier.attestation.statement.androidkey.NullAndroidKeyAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.androidsafetynet.NullAndroidSafetyNetAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.none.NoneAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.packed.NullPackedAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.tpm.NullTPMAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.statement.u2f.NullFIDOU2FAttestationStatementVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.certpath.NullCertPathTrustworthinessVerifier;
import com.webauthn4j.verifier.attestation.trustworthiness.self.NullSelfAttestationTrustworthinessVerifier;
import com.webauthn4j.verifier.exception.*;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

class RegistrationDataVerifierTest {

    private final RegistrationDataVerifier target;

    public RegistrationDataVerifierTest() {
        ObjectConverter objectConverter = new ObjectConverter();

        target = new RegistrationDataVerifier(Arrays.asList(
                new NoneAttestationStatementVerifier(),
                new NullFIDOU2FAttestationStatementVerifier(),
                new NullPackedAttestationStatementVerifier(),
                new NullTPMAttestationStatementVerifier(),
                new NullAndroidKeyAttestationStatementVerifier(),
                new NullAndroidSafetyNetAttestationStatementVerifier()
        ),
                new NullCertPathTrustworthinessVerifier(),
                new NullSelfAttestationTrustworthinessVerifier(),
                new ArrayList<>(),
                objectConverter);
    }

    @Test
    void verifyAlg_test(){
        List<PublicKeyCredentialParameters> pubKeyCredParams = Arrays.asList(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.ES256), new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256));
        target.verifyAlg(COSEAlgorithmIdentifier.ES256, pubKeyCredParams);
    }

    @Test
    void verifyAlg_not_allowed_alg_test(){
        List<PublicKeyCredentialParameters> pubKeyCredParams = Collections.singletonList(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, COSEAlgorithmIdentifier.RS256));
        assertThrows(NotAllowedAlgorithmException.class,
                () -> target.verifyAlg(COSEAlgorithmIdentifier.ES256, pubKeyCredParams)
        );
    }

    @Test
    void verifyAuthenticatorDataField_test() {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], (byte) 0, 0);
        assertThrows(ConstraintViolationException.class,
                () -> target.verifyAuthenticatorDataField(authenticatorData)
        );
    }

    @Test
    void verifyUVUPFlags_not_required_test() {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], (byte) 0, 0);
        target.verifyUVUPFlags(authenticatorData, false, false);
    }

    @Test
    void verifyUVUPFlags_required_test() {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], (byte) (AuthenticatorData.BIT_UP | AuthenticatorData.BIT_UV), 0);
        target.verifyUVUPFlags(authenticatorData, true, true);
    }

    @Test
    void verifyUVUPFlags_UserNotVerifiedException_test() {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], (byte) 0, 0);
        assertThrows(UserNotVerifiedException.class,
                () -> target.verifyUVUPFlags(authenticatorData, true, false)
        );
    }

    @Test
    void verifyUVUPFlags_UserNotPresentException_test() {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], (byte) 0, 0);
        assertThrows(UserNotPresentException.class,
                () -> target.verifyUVUPFlags(authenticatorData, false, true)
        );
    }

    @Test
    void verifyBEBSFlags_only_BSFlag_set_test() {
        AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = new AuthenticatorData<>(new byte[32], AuthenticatorData.BIT_BS, 0);
        assertThrows(IllegalBackupStateException.class,
                () -> target.verifyBEBSFlags(authenticatorData)
        );
    }

    @Test
    void verifyCredentialIdLength_too_long_credentialId_test(){
        assertThrows(CredentialIdTooLongException.class,
                () -> target.verifyCredentialIdLength(new byte[1024])
        );
    }

    @Test
    void getCustomRegistrationVerifiers() {
        CustomRegistrationVerifier customRegistrationVerifier = mock(CustomRegistrationVerifier.class);
        target.getCustomRegistrationVerifiers().add(customRegistrationVerifier);
        assertThat(target.getCustomRegistrationVerifiers()).contains(customRegistrationVerifier);
    }

    @Test
    void getter_setter_test() {
        target.setOriginVerifier(new TestOriginVerifier());
        assertThat(target.getOriginVerifier()).isInstanceOf(TestOriginVerifier.class);
    }

    private static class TestOriginVerifier extends OriginVerifierImpl {
    }
}
