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

package com.webauthn4j.validator.attestation.statement;

import com.webauthn4j.response.attestation.statement.AttestationStatement;
import com.webauthn4j.validator.RegistrationObject;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;

public abstract class AbstractStatementValidator<T extends AttestationStatement> implements AttestationStatementValidator {
    @Override
    public boolean supports(RegistrationObject registrationObject) {
        AttestationStatement attestationStatement = registrationObject.getAttestationObject().getAttestationStatement();

        ParameterizedType parameterizedType = (ParameterizedType) getClass().getGenericSuperclass();
        Type actualTypeArgument = parameterizedType.getActualTypeArguments()[0];

        if (actualTypeArgument instanceof Class) {
            Class<?> aClass = (Class<?>) actualTypeArgument;

            return aClass.isAssignableFrom(attestationStatement.getClass());
        }

        return false;
    }
}
