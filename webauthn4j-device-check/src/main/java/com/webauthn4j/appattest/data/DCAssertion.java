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

package com.webauthn4j.appattest.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

public class DCAssertion {

    private final byte[] signature;
    private final byte[] authenticatorData;

    @JsonCreator
    public DCAssertion(
            @NonNull @JsonProperty("signature") byte[] signature,
            @NonNull @JsonProperty("authenticatorData") byte[] authenticatorData) {
        AssertUtil.notNull(signature, "signature must not be null");
        AssertUtil.notNull(authenticatorData, "authenticatorData must not be null");
        this.signature = signature;
        this.authenticatorData = authenticatorData;
    }

    @JsonGetter("signature")
    public @Nullable byte[] getSignature() {
        return signature;
    }

    @JsonGetter("authenticatorData")
    public @Nullable byte[] getAuthenticatorData() {
        return authenticatorData;
    }

}
