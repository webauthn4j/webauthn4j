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

import com.webauthn4j.data.CoreRegistrationData;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.util.ArrayUtil;
import org.jetbrains.annotations.Nullable;

import java.util.Arrays;

public class DCAttestationData extends CoreRegistrationData {

    private final byte[] keyId;

    public DCAttestationData(
            @Nullable byte[] keyId,
            @Nullable AttestationObject attestationObject,
            @Nullable byte[] attestationObjectBytes,
            @Nullable byte[] clientDataHash) {
        super(attestationObject, attestationObjectBytes, clientDataHash);
        this.keyId = ArrayUtil.clone(keyId);
    }

    public @Nullable byte[] getKeyId() {
        return ArrayUtil.clone(keyId);
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        DCAttestationData that = (DCAttestationData) o;
        return Arrays.equals(keyId, that.keyId);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + Arrays.hashCode(keyId);
        return result;
    }
}
