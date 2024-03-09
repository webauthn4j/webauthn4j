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

package com.webauthn4j.data.extension.authenticator;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.util.ArrayUtil;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.Arrays;
import java.util.Objects;

public class HMACGetSecretAuthenticatorInput {

    private final COSEKey keyAgreement;
    private final byte[] saltEnc;
    private final byte[] saltAuth;

    @JsonCreator
    public HMACGetSecretAuthenticatorInput(
            @NonNull @JsonProperty("1") COSEKey keyAgreement,
            @NonNull @JsonProperty("2") byte[] saltEnc,
            @NonNull @JsonProperty("3") byte[] saltAuth) {
        this.keyAgreement = keyAgreement;
        this.saltEnc = ArrayUtil.clone(saltEnc);
        this.saltAuth = ArrayUtil.clone(saltAuth);
    }

    public @NonNull COSEKey getKeyAgreement() {
        return keyAgreement;
    }

    public @NonNull byte[] getSaltEnc() {
        return ArrayUtil.clone(saltEnc);
    }

    public @NonNull byte[] getSaltAuth() {
        return ArrayUtil.clone(saltAuth);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        HMACGetSecretAuthenticatorInput that = (HMACGetSecretAuthenticatorInput) o;
        return Objects.equals(keyAgreement, that.keyAgreement) && Arrays.equals(saltEnc, that.saltEnc) && Arrays.equals(saltAuth, that.saltAuth);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(keyAgreement);
        result = 31 * result + Arrays.hashCode(saltEnc);
        result = 31 * result + Arrays.hashCode(saltAuth);
        return result;
    }
}
