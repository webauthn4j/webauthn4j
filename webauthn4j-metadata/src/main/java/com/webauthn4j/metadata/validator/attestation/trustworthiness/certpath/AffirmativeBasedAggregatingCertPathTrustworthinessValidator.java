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

package com.webauthn4j.metadata.validator.attestation.trustworthiness.certpath;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.statement.CertificateBaseAttestationStatement;
import com.webauthn4j.metadata.exception.AggregatedValidationException;
import com.webauthn4j.validator.attestation.trustworthiness.certpath.CertPathTrustworthinessValidator;
import com.webauthn4j.validator.exception.ValidationException;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public class AffirmativeBasedAggregatingCertPathTrustworthinessValidator implements CertPathTrustworthinessValidator {

    private final CertPathTrustworthinessValidator[] certPathTrustworthinessValidators;

    public AffirmativeBasedAggregatingCertPathTrustworthinessValidator(CertPathTrustworthinessValidator... certPathTrustworthinessValidators){
        this.certPathTrustworthinessValidators = certPathTrustworthinessValidators;
    }


    @Override
    public void validate(@NonNull AAGUID aaguid, @NonNull CertificateBaseAttestationStatement attestationStatement, @NonNull Instant timestamp) {

        List<ValidationException> exceptions = new ArrayList<>();

        for (CertPathTrustworthinessValidator certPathTrustworthinessValidator : certPathTrustworthinessValidators) {
            try{
                certPathTrustworthinessValidator.validate(aaguid, attestationStatement, timestamp);
                return;
            }
            catch (ValidationException e){
                exceptions.add(e);
            }
        }
        throw new AggregatedValidationException("None certPathTrustworthinessValidators validated successfully.", exceptions);
    }
}
