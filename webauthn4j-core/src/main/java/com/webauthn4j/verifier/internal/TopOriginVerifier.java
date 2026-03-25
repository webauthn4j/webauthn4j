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

package com.webauthn4j.verifier.internal;

import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.server.OriginPredicate;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.verifier.AuthenticationDataVerifier;
import com.webauthn4j.verifier.AuthenticationObject;
import com.webauthn4j.verifier.RegistrationObject;
import com.webauthn4j.verifier.exception.BadTopOriginException;
import com.webauthn4j.verifier.exception.CrossOriginException;
import org.jetbrains.annotations.NotNull;

import java.util.Objects;

/**
 * Verifier for cross-origin authentication.
 * <p>
 * Implements WebAuthn Level 3 § 7.2 Step 13 (crossOrigin verification) and Step 14 (topOrigin verification).
 * While topOrigin verification provides a more detailed allowlist-based validation,
 * crossOrigin flag verification is also performed for backward compatibility.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">WebAuthn Level 3 § 7.2 Verifying an Authentication Assertion</a>
 */
public class TopOriginVerifier {

    //~ Instance fields
    // ================================================================================================
    private boolean forceBlockCrossOrigin = false;

    // ~ Methods
    // ========================================================================================================

    public void verify(@NotNull RegistrationObject registrationObject) {
        AssertUtil.notNull(registrationObject, "registrationObject must not be null");
        CollectedClientData collectedClientData = registrationObject.getCollectedClientData();
        ServerProperty serverProperty = registrationObject.getServerProperty();
        verify(collectedClientData, serverProperty);
    }

    public void verify(@NotNull AuthenticationObject authenticationObject) {
        AssertUtil.notNull(authenticationObject, "authenticationObject must not be null");
        CollectedClientData collectedClientData = authenticationObject.getCollectedClientData();
        ServerProperty serverProperty = authenticationObject.getServerProperty();
        verify(collectedClientData, serverProperty);
    }

    protected void verify(@NotNull CollectedClientData collectedClientData, @NotNull ServerProperty serverProperty) {
        AssertUtil.notNull(collectedClientData, "collectedClientData must not be null");
        AssertUtil.notNull(serverProperty, "serverProperty must not be null");

        Boolean clientCrossOrigin = collectedClientData.getCrossOrigin();
        Origin clientTopOrigin = collectedClientData.getTopOrigin();
        OriginPredicate expectedTopOriginPredicate = serverProperty.getTopOriginPredicate();

        //spec| Registration Step10 & Authentication Step13
        //spec| If C.crossOrigin is present and set to true,
        //spec| verify that the Relying Party expects this credential to be used/created within an iframe that is not same-origin with its ancestors.
        if(Objects.equals(clientCrossOrigin, Boolean.TRUE)){
            // Deprecated API check
            if(forceBlockCrossOrigin){
                throw new CrossOriginException("Cross-origin request is prohibited. Relax AuthenticationDataVerifier config if necessary.");
            }
            // Modern API: RP must explicitly allow cross-origin by setting topOriginPredicate and provide valid topOrigin
            if (expectedTopOriginPredicate == null || !expectedTopOriginPredicate.test(clientTopOrigin)) {
                throw new BadTopOriginException("The collectedClientData topOrigin '" + clientTopOrigin + "' doesn't match any of the preconfigured server topOrigin.");
            }
        }

        //spec| Registration Step11 & Authentication Step14
        //spec| If C.topOrigin is present:
        //spec| - Verify that the Relying Party expects this credential to be used/created within an iframe that is not same-origin with its ancestors.
        //spec| - Verify that the value of C.topOrigin matches the origin of a page that the Relying Party expects to be sub-framed within.
        //spec|   See §13.4.9 Validating the origin of a credential for guidance.
        if(clientTopOrigin != null){
            // Note: Although well-behaved browsers guarantee crossOrigin=true when topOrigin is present,
            // we verify RP expectations here independently per the spec structure.
            // This provides defense-in-depth against clients that might send topOrigin without proper crossOrigin flag.

            // Deprecated API check
            if(forceBlockCrossOrigin){
                throw new CrossOriginException("Cross-origin request is prohibited. Relax AuthenticationDataVerifier config if necessary.");
            }
            // Modern API: RP must explicitly allow cross-origin by setting topOriginPredicate and provide valid topOrigin
            if (expectedTopOriginPredicate == null || !expectedTopOriginPredicate.test(clientTopOrigin)) {
                throw new BadTopOriginException("The collectedClientData topOrigin '" + clientTopOrigin + "' doesn't match any of the preconfigured server topOrigin.");
            }
        }
    }

    /**
     * @deprecated This method was added to support {@link AuthenticationDataVerifier#setCrossOriginAllowed}, but it is deprecated along with {@link AuthenticationDataVerifier#setCrossOriginAllowed}.
     * Use {@link ServerProperty.Builder#anyTopOrigin()} or {@link ServerProperty.Builder#topOriginPredicate(OriginPredicate)} instead.
     */
    @Deprecated
    public void setForceBlockCrossOrigin(boolean forceBlockCrossOrigin) {
        this.forceBlockCrossOrigin = forceBlockCrossOrigin;
    }

    @Deprecated
    public boolean isForceBlockCrossOrigin() {
        return forceBlockCrossOrigin;
    }
}
