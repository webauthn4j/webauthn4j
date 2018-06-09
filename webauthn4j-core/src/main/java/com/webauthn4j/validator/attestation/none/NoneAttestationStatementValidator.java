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

package com.webauthn4j.validator.attestation.none;

import com.webauthn4j.attestation.statement.AttestationStatement;
import com.webauthn4j.attestation.statement.AttestationType;
import com.webauthn4j.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.attestation.AttestationStatementValidator;

public class NoneAttestationStatementValidator implements AttestationStatementValidator {

    @Override
    public AttestationType validate(RegistrationObject registrationObject) {
        return AttestationType.NONE;
    }

    @Override
    public boolean supports(RegistrationObject registrationObject) {
        AttestationStatement attestationStatement = registrationObject.getAttestationObject().getAttestationStatement();
        return NoneAttestationStatement.class.isAssignableFrom(attestationStatement.getClass());
    }
}
