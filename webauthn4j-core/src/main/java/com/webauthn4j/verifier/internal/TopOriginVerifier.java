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

        if(Objects.equals(clientCrossOrigin, Boolean.TRUE)){
            if(forceBlockCrossOrigin){
                throw new CrossOriginException("Cross-origin request is prohibited. Relax AuthenticationDataVerifier config if necessary.");
            }
            if (expectedTopOriginPredicate == null || !expectedTopOriginPredicate.test(clientTopOrigin)) {
                throw new BadTopOriginException("The collectedClientData topOrigin '" + clientTopOrigin + "' doesn't match any of the preconfigured server topOrigin.");
            }
        }
        else{ // false or null
            //nop
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
