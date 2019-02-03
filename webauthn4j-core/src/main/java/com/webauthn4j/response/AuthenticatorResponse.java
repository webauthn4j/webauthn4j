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

import com.webauthn4j.util.ArrayUtil;

import java.io.Serializable;

abstract class AuthenticatorResponse implements Serializable {

    // ~ Instance fields
    // ================================================================================================

    private byte[] clientDataJSON;

    // ~ Constructor
    // ========================================================================================================

    AuthenticatorResponse(byte[] clientDataJSON) {
        this.clientDataJSON = clientDataJSON;
    }

    public byte[] getClientDataJSON() {
        return ArrayUtil.clone(clientDataJSON);
    }
}
