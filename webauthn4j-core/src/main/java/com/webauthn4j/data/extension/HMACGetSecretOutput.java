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

public class HMACGetSecretOutput {

    @JsonProperty
    private final byte[] output1;
    @JsonProperty
    private final byte[] output2;

    @JsonCreator
    public HMACGetSecretOutput(
            @NotNull @JsonProperty("output1") byte[] output1,
            @Nullable @JsonProperty("output2") byte[] output2) {
        this.output1 = ArrayUtil.clone(output1);
        this.output2 = ArrayUtil.clone(output2);
    }

    public HMACGetSecretOutput(@NotNull byte[] output1) {
        this.output1 = ArrayUtil.clone(output1);
        this.output2 = null;
    }

    public @NotNull byte[] getOutput1() {
        return ArrayUtil.clone(output1);
    }

    public @Nullable byte[] getOutput2() {
        return ArrayUtil.clone(output2);
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        HMACGetSecretOutput that = (HMACGetSecretOutput) o;
        return Arrays.equals(output1, that.output1) && Arrays.equals(output2, that.output2);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(output1);
        result = 31 * result + Arrays.hashCode(output2);
        return result;
    }
}
