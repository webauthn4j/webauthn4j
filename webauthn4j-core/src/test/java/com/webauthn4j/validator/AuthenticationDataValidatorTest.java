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

import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import com.webauthn4j.validator.exception.CrossOriginException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticationDataValidatorTest {

    private final AuthenticationDataValidator target = new AuthenticationDataValidator();

    @Test
    void validateAuthenticatorData_with_non_null_AttestedCredentialData(@Mock AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData) {
        AttestedCredentialData attestedCredentialData = mock(AttestedCredentialData.class);
        when(authenticatorData.getAttestedCredentialData()).thenReturn(attestedCredentialData);
        assertThatThrownBy(() -> target.validateAuthenticatorData(authenticatorData)).isInstanceOf(ConstraintViolationException.class);
    }

    @Test
    void validateClientDataCrossOrigin_with_expected_crossOrigin_test() {
        target.setCrossOriginAllowed(true);
        Origin origin = new Origin("http://example.com");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.CREATE, TestDataUtil.createChallenge(), origin, true, null);
        target.validateClientDataCrossOrigin(collectedClientData);
    }

    @Test
    void validateClientDataCrossOrigin_with_unexpected_crossOrigin_test() {
        Origin origin = new Origin("http://example.com");

        CollectedClientData collectedClientData = new CollectedClientData(ClientDataType.CREATE, TestDataUtil.createChallenge(), origin, true, null);
        assertThrows(CrossOriginException.class,
                () -> target.validateClientDataCrossOrigin(collectedClientData)
        );
    }

    @Test
    void getCustomAuthenticationValidators() {
        CustomAuthenticationValidator customAuthenticationValidator = mock(CustomAuthenticationValidator.class);
        target.getCustomAuthenticationValidators().add(customAuthenticationValidator);
        assertThat(target.getCustomAuthenticationValidators()).contains(customAuthenticationValidator);
    }

    @Test
    void getter_setter_test(){
        target.setOriginValidator(new TestOriginValidator());
        assertThat(target.getOriginValidator()).isInstanceOf(TestOriginValidator.class);
        target.setCrossOriginAllowed(true);
        assertThat(target.isCrossOriginAllowed()).isTrue();
    }

    private static class TestOriginValidator extends OriginValidatorImpl {
    }

}