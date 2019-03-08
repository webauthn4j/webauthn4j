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

package com.webauthn4j.response;

import com.webauthn4j.request.AuthenticatorTransport;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.CollectionUtil;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * WebAuthn registration context
 */
public class WebAuthnRegistrationContext extends AbstractWebAuthnContext {

    // ~ Instance fields
    // ================================================================================================

    private final byte[] attestationObject;

    // ~ Constructor
    // ========================================================================================================

    public WebAuthnRegistrationContext(byte[] clientDataJSON,
                                       byte[] attestationObject,
                                       String clientExtensionsJSON,
                                       ServerProperty serverProperty,
                                       boolean userVerificationRequired,
                                       boolean userPresenceRequired,
                                       List<String> expectedExtensionIds) {

        super(
                clientDataJSON,
                clientExtensionsJSON,
                serverProperty,
                userVerificationRequired,
                userPresenceRequired,
                CollectionUtil.unmodifiableList(expectedExtensionIds)
        );
        this.attestationObject = attestationObject;
    }

    public WebAuthnRegistrationContext(byte[] clientDataJSON,
                                       byte[] attestationObject,
                                       String clientExtensionsJSON,
                                       ServerProperty serverProperty,
                                       boolean userVerificationRequired,
                                       List<String> expectedExtensionIds) {

        this(
                clientDataJSON,
                attestationObject,
                clientExtensionsJSON,
                serverProperty,
                userVerificationRequired,
                true,
                expectedExtensionIds
        );
    }

    public WebAuthnRegistrationContext(byte[] clientDataJSON,
                                       byte[] attestationObject,
                                       ServerProperty serverProperty,
                                       boolean userVerificationRequired) {

        this(
                clientDataJSON,
                attestationObject,
                null,
                serverProperty,
                userVerificationRequired,
                Collections.emptyList()
        );
    }

    public byte[] getAttestationObject() {
        return ArrayUtil.clone(attestationObject);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        WebAuthnRegistrationContext that = (WebAuthnRegistrationContext) o;
        return Arrays.equals(attestationObject, that.attestationObject);
    }

    @Override
    public int hashCode() {

        int result = super.hashCode();
        result = 31 * result + Arrays.hashCode(attestationObject);
        return result;
    }
}
