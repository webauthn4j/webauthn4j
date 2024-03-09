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

import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.util.ArrayUtil;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Arrays;
import java.util.Objects;

public class CoreRegistrationData {

    private final AttestationObject attestationObject;
    private final byte[] attestationObjectBytes;
    private final byte[] clientDataHash;

    public CoreRegistrationData(
            @Nullable AttestationObject attestationObject,
            @Nullable byte[] attestationObjectBytes,
            @Nullable byte[] clientDataHash) {
        this.attestationObject = attestationObject;
        this.attestationObjectBytes = ArrayUtil.clone(attestationObjectBytes);
        this.clientDataHash = ArrayUtil.clone(clientDataHash);
    }

    public @Nullable AttestationObject getAttestationObject() {
        return attestationObject;
    }

    public @Nullable byte[] getAttestationObjectBytes() {
        return ArrayUtil.clone(attestationObjectBytes);
    }

    public @Nullable byte[] getClientDataHash() {
        return ArrayUtil.clone(clientDataHash);
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CoreRegistrationData that = (CoreRegistrationData) o;
        return Objects.equals(attestationObject, that.attestationObject) &&
                Arrays.equals(attestationObjectBytes, that.attestationObjectBytes) &&
                Arrays.equals(clientDataHash, that.clientDataHash);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(attestationObject);
        result = 31 * result + Arrays.hashCode(attestationObjectBytes);
        result = 31 * result + Arrays.hashCode(clientDataHash);
        return result;
    }

    @Override
    public String toString() {
        return "CoreRegistrationData(" +
                "attestationObject=" + attestationObject +
                ", attestationObjectBytes=" + ArrayUtil.toHexString(attestationObjectBytes) +
                ", clientDataHash=" + ArrayUtil.toHexString(clientDataHash) +
                ')';
    }
}
