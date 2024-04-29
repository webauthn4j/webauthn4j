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

package com.webauthn4j.validator.attestation.statement.apple;

import com.webauthn4j.data.attestation.statement.AppleAnonymousAttestationStatement;
import com.webauthn4j.data.attestation.statement.AttestationType;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.validator.CoreRegistrationObject;
import com.webauthn4j.validator.attestation.statement.AbstractStatementValidator;
import org.jetbrains.annotations.NotNull;

public class NullAppleAnonymousAttestationStatementValidator extends AbstractStatementValidator<AppleAnonymousAttestationStatement> {
    @Override
    public @NotNull AttestationType validate(@NotNull CoreRegistrationObject registrationObject) {
        AssertUtil.notNull(registrationObject, "registrationObject must not be null");
        if (!supports(registrationObject)) {
            throw new IllegalArgumentException("Specified format is not supported by " + this.getClass().getName());
        }

        return AttestationType.NONE;
    }
}
