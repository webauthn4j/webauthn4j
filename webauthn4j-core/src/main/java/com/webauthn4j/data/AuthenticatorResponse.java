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

package com.webauthn4j.data;

import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;


/**
 * Authenticators respond to Relying Party requests by returning an object derived from the AuthenticatorResponse.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#authenticatorresponse">§5.2. Authenticator Responses (interface AuthenticatorResponse)</a>
 */
public abstract class AuthenticatorResponse {

    // ~ Instance fields
    // ================================================================================================

    private final byte[] clientDataJSON;

    // ~ Constructor
    // ========================================================================================================

    AuthenticatorResponse(@NonNull byte[] clientDataJSON) {
        AssertUtil.notNull(clientDataJSON, "clientDataJSON must not be null");
        this.clientDataJSON = clientDataJSON;
    }

    public @NonNull byte[] getClientDataJSON() {
        return ArrayUtil.clone(clientDataJSON);
    }

    @Override
    public String toString() {
        return "AuthenticatorResponse(" +
                "clientDataJSON=" + ArrayUtil.toHexString(clientDataJSON) +
                ')';
    }
}
