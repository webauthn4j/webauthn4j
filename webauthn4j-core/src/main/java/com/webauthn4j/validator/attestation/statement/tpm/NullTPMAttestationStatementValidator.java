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

package com.webauthn4j.validator.attestation.statement.tpm;

import com.webauthn4j.data.attestation.statement.AttestationType;
import com.webauthn4j.data.attestation.statement.TPMAttestationStatement;
import com.webauthn4j.validator.CoreRegistrationObject;
import com.webauthn4j.validator.attestation.statement.AbstractStatementValidator;

public class NullTPMAttestationStatementValidator extends AbstractStatementValidator<TPMAttestationStatement> {
    @Override
    public AttestationType validate(CoreRegistrationObject registrationObject) {
        if (!supports(registrationObject)) {
            throw new IllegalArgumentException("Specified format is not supported by " + this.getClass().getName());
        }

        return AttestationType.NONE;
    }
}
