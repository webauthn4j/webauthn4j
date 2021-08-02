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

import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.validator.exception.BadOriginException;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.Set;

public class OriginValidatorImpl implements OriginValidator {

    //~ Instance fields
    // ================================================================================================


    // ~ Methods
    // ========================================================================================================

    @Override
    public void validate(@NonNull RegistrationObject registrationObject) {
        AssertUtil.notNull(registrationObject, "registrationObject must not be null");
        CollectedClientData collectedClientData = registrationObject.getCollectedClientData();
        ServerProperty serverProperty = registrationObject.getServerProperty();
        validate(collectedClientData, serverProperty);
    }

    @Override
    public void validate(@NonNull AuthenticationObject authenticationObject) {
        AssertUtil.notNull(authenticationObject, "authenticationObject must not be null");
        CollectedClientData collectedClientData = authenticationObject.getCollectedClientData();
        ServerProperty serverProperty = authenticationObject.getServerProperty();
        validate(collectedClientData, serverProperty);
    }

    private void validate(@NonNull Origin clientOrigin, @NonNull Set<Origin> serverOrigins) {
        AssertUtil.notNull(clientOrigin, "client origin must not be null");
        AssertUtil.notNull(serverOrigins, "server origins set must not be null");
        if (!serverOrigins.contains(clientOrigin)) {
            throw new BadOriginException("The collectedClientData '" + clientOrigin + "' origin doesn't match any of the preconfigured server origin.");
        }
    }

    protected void validate(@NonNull CollectedClientData collectedClientData, @NonNull ServerProperty serverProperty) {
        AssertUtil.notNull(collectedClientData, "collectedClientData must not be null");
        AssertUtil.notNull(serverProperty, "serverProperty must not be null");

        final Origin clientOrigin = collectedClientData.getOrigin();
        validate(clientOrigin, serverProperty.getOrigins());
    }

}
