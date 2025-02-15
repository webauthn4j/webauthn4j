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

package com.webauthn4j.data.extension;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.util.ArrayUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Arrays;

public class HMACGetSecretInput {

    @JsonProperty
    private final byte[] salt1;
    @JsonProperty
    private final byte[] salt2;

    @JsonCreator
    public HMACGetSecretInput(
            @NotNull @JsonProperty("salt1") byte[] salt1,
            @Nullable @JsonProperty("salt2") byte[] salt2) {
        this.salt1 = ArrayUtil.clone(salt1);
        this.salt2 = ArrayUtil.clone(salt2);
    }

    public HMACGetSecretInput(@NotNull byte[] salt1) {
        this.salt1 = ArrayUtil.clone(salt1);
        this.salt2 = null;
    }

    public @NotNull byte[] getSalt1() {
        return ArrayUtil.clone(salt1);
    }

    public @Nullable byte[] getSalt2() {
        return ArrayUtil.clone(salt2);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        HMACGetSecretInput that = (HMACGetSecretInput) o;
        return Arrays.equals(salt1, that.salt1) && Arrays.equals(salt2, that.salt2);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(salt1);
        result = 31 * result + Arrays.hashCode(salt2);
        return result;
    }
}
