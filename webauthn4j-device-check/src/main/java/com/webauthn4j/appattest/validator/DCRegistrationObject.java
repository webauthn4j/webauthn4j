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

package com.webauthn4j.appattest.validator;

import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.server.CoreServerProperty;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.validator.CoreRegistrationObject;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.time.Instant;
import java.util.Arrays;

public class DCRegistrationObject extends CoreRegistrationObject {

    private final byte[] keyId;


    public DCRegistrationObject(
            @NonNull byte[] keyId,
            @NonNull AttestationObject attestationObject,
            @NonNull byte[] attestationObjectBytes,
            @NonNull byte[] clientDataHash,
            @NonNull CoreServerProperty serverProperty,
            @NonNull Instant timestamp) {
        super(attestationObject, attestationObjectBytes, clientDataHash, serverProperty, timestamp);
        this.keyId = ArrayUtil.clone(keyId);
    }

    public DCRegistrationObject(
            @NonNull byte[] keyId,
            @NonNull AttestationObject attestationObject,
            @NonNull byte[] attestationObjectBytes,
            @NonNull byte[] clientDataHash,
            @NonNull CoreServerProperty serverProperty) {
        super(attestationObject, attestationObjectBytes, clientDataHash, serverProperty);
        this.keyId = ArrayUtil.clone(keyId);
    }

    public @NonNull byte[] getKeyId() {
        return ArrayUtil.clone(keyId);
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        DCRegistrationObject that = (DCRegistrationObject) o;
        return Arrays.equals(keyId, that.keyId);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + Arrays.hashCode(keyId);
        return result;
    }
}
