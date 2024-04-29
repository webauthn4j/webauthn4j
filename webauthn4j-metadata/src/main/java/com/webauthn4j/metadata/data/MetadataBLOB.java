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

package com.webauthn4j.metadata.data;

import com.webauthn4j.data.jws.JWS;
import com.webauthn4j.data.jws.JWSHeader;
import org.jetbrains.annotations.NotNull;

public class MetadataBLOB {

    @NotNull
    private final JWS<MetadataBLOBPayload> jws;

    public MetadataBLOB(@NotNull JWS<MetadataBLOBPayload> jws) {
        this.jws = jws;
    }

    public @NotNull JWSHeader getHeader(){
        return jws.getHeader();
    }

    public @NotNull MetadataBLOBPayload getPayload(){
        return jws.getPayload();
    }

    public @NotNull byte[] getSignature() {
        return jws.getSignature();
    }

    /**
     * Validates signature.
     *
     * @return true if it pass validation
     */
    public boolean isValidSignature() {
        return jws.isValidSignature();
    }

}
