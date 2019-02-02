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

package com.webauthn4j.validator;


import com.webauthn4j.registry.Registry;
import com.webauthn4j.response.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.ecdaa.ECDAATrustworthinessValidator;
import com.webauthn4j.validator.attestation.trustworthiness.self.SelfAttestationTrustworthinessValidator;
import com.webauthn4j.validator.exception.MaliciousDataException;
import com.webauthn4j.validator.exception.UserNotPresentException;
import com.webauthn4j.validator.exception.UserNotVerifiedException;
import org.junit.Test;

import java.util.Collections;

import static org.mockito.Mockito.mock;

public class WebAuthnRegistrationContextValidatorTest {

    CertPathTrustworthinessValidator certPathTrustworthinessValidatorMock = mock(CertPathTrustworthinessValidator.class);
    ECDAATrustworthinessValidator ecdaaTrustworthinessValidatorMock = mock(ECDAATrustworthinessValidator.class);
    SelfAttestationTrustworthinessValidator selfAttestationTrustworthinessValidator = mock(SelfAttestationTrustworthinessValidator.class);
    Registry registry = new Registry();

    @Test
    public void constructor_test() {
        WebAuthnRegistrationContextValidator validator;
        validator = new WebAuthnRegistrationContextValidator(
                        Collections.emptyList(),
                        certPathTrustworthinessValidatorMock,
                        ecdaaTrustworthinessValidatorMock);
        validator = new WebAuthnRegistrationContextValidator(
                        Collections.emptyList(),
                        certPathTrustworthinessValidatorMock,
                        ecdaaTrustworthinessValidatorMock,
                        registry);
        validator = new WebAuthnRegistrationContextValidator(
                Collections.emptyList(),
                certPathTrustworthinessValidatorMock,
                ecdaaTrustworthinessValidatorMock,
                selfAttestationTrustworthinessValidator,
                registry);
    }

    @Test(expected = MaliciousDataException.class)
    public void validateAuthenticatorDataField_test(){
        AuthenticatorData authenticatorData = new AuthenticatorData(null, (byte)0, 0);
        WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator().validateAuthenticatorDataField(authenticatorData);
    }

    @Test
    public void validateUVUPFlags_not_required_test(){
        AuthenticatorData authenticatorData = new AuthenticatorData(null, (byte)0, 0);
        WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator().validateUVUPFlags(authenticatorData, false, false);
    }

    @Test
    public void validateUVUPFlags_required_test(){
        AuthenticatorData authenticatorData = new AuthenticatorData(null, (byte)(AuthenticatorData.BIT_UP | AuthenticatorData.BIT_UV), 0);
        WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator().validateUVUPFlags(authenticatorData, true, true);
    }

    @Test(expected = UserNotVerifiedException.class)
    public void validateUVUPFlags_UserNotVerifiedException_test(){
        AuthenticatorData authenticatorData = new AuthenticatorData(null, (byte)0, 0);
        WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator().validateUVUPFlags(authenticatorData, true, false);
    }

    @Test(expected = UserNotPresentException.class)
    public void validateUVUPFlags_UserNotPresentException_test(){
        AuthenticatorData authenticatorData = new AuthenticatorData(null, (byte)0, 0);
        WebAuthnRegistrationContextValidator.createNonStrictRegistrationContextValidator().validateUVUPFlags(authenticatorData, false, true);
    }



}