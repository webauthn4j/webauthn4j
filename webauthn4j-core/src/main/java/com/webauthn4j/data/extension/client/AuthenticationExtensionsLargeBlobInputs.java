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
import com.webauthn4j.data.extension.LargeBlobSupport;
import com.webauthn4j.util.ArrayUtil;
import org.jetbrains.annotations.Nullable;

import java.util.Arrays;
import java.util.Objects;

/**
 * Data class representing the WebIDL AuthenticationExtensionsLargeBlobInputs dictionary.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionslargeblobinputs">
 * §10.5. Large blob storage extension (largeBlob)</a>
 */
public class AuthenticationExtensionsLargeBlobInputs {

    private final LargeBlobSupport support;
    private final Boolean read;
    private final byte[] write;

    @JsonCreator
    public AuthenticationExtensionsLargeBlobInputs(
            @Nullable @JsonProperty("support") LargeBlobSupport support,
            @Nullable @JsonProperty("read") Boolean read,
            @Nullable @JsonProperty("write") byte[] write) {
        this.support = support;
        this.read = read;
        this.write = ArrayUtil.clone(write);
    }

    public @Nullable LargeBlobSupport getSupport() {
        return support;
    }

    public @Nullable Boolean getRead() {
        return read;
    }

    public @Nullable byte[] getWrite() {
        return ArrayUtil.clone(write);
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationExtensionsLargeBlobInputs that = (AuthenticationExtensionsLargeBlobInputs) o;
        return support == that.support && Objects.equals(read, that.read) && Arrays.equals(write, that.write);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(support, read);
        result = 31 * result + Arrays.hashCode(write);
        return result;
    }
}
