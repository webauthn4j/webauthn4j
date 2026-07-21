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

package com.webauthn4j.data.extension.client;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.util.ArrayUtil;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.Arrays;

/**
 * @see <a href="https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionsprfvalues">
 * §10.1.4. Pseudo-random function extension (prf)</a>
 */
public class AuthenticationExtensionsPRFValues {

    private final byte[] first;
    private final byte[] second;

    @JsonCreator
    public AuthenticationExtensionsPRFValues(
            @NotNull @JsonProperty("first") byte[] first,
            @Nullable @JsonProperty("second") byte[] second) {
        this.first = ArrayUtil.clone(first);
        this.second = ArrayUtil.clone(second);
    }

    public @NotNull byte[] getFirst() {
        return ArrayUtil.clone(first);
    }

    public @Nullable byte[] getSecond() {
        return ArrayUtil.clone(second);
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationExtensionsPRFValues that = (AuthenticationExtensionsPRFValues) o;
        return Arrays.equals(first, that.first) && Arrays.equals(second, that.second);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(first);
        result = 31 * result + Arrays.hashCode(second);
        return result;
    }
}
