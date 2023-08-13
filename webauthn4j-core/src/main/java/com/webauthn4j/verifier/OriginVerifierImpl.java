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

package com.webauthn4j.verifier;

import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.server.OriginPredicate;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.verifier.exception.BadOriginException;
import org.jetbrains.annotations.NotNull;

/**
 * Verifier for origin validation.
 * <p>
 * Implements WebAuthn Level 3 § 7.2 Step 12 (origin verification).
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">WebAuthn Level 3 § 7.2 Verifying an Authentication Assertion</a>
 */
public class OriginVerifierImpl implements OriginVerifier {

    //~ Instance fields
    // ================================================================================================


    // ~ Methods
    // ========================================================================================================

    @Override
    public void verify(@NotNull RegistrationObject registrationObject) {
        AssertUtil.notNull(registrationObject, "registrationObject must not be null");
        CollectedClientData collectedClientData = registrationObject.getCollectedClientData();
        ServerProperty serverProperty = registrationObject.getServerProperty();
        verify(collectedClientData, serverProperty);
    }

    @Override
    public void verify(@NotNull AuthenticationObject authenticationObject) {
        AssertUtil.notNull(authenticationObject, "authenticationObject must not be null");
        CollectedClientData collectedClientData = authenticationObject.getCollectedClientData();
        ServerProperty serverProperty = authenticationObject.getServerProperty();
        verify(collectedClientData, serverProperty);
    }

    protected void verify(@NotNull CollectedClientData collectedClientData, @NotNull ServerProperty serverProperty) {
        AssertUtil.notNull(collectedClientData, "collectedClientData must not be null");
        AssertUtil.notNull(serverProperty, "serverProperty must not be null");

        final Origin clientOrigin = collectedClientData.getOrigin();
        if (!serverProperty.getOriginPredicate().test(clientOrigin)) {
            OriginPredicate predicate = serverProperty.getOriginPredicate();
            String expectedDescription;
            try {
                expectedDescription = predicate.toString();
            } catch (Exception e) {
                expectedDescription = predicate.getClass().getName();
            }
            throw new BadOriginException("The collectedClientData origin '" + clientOrigin + "' doesn't match expected: " + expectedDescription, predicate, clientOrigin);
        }
    }

}
