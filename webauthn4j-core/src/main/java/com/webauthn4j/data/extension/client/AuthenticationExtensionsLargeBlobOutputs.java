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
import org.jetbrains.annotations.Nullable;

import java.util.Arrays;
import java.util.Objects;

/**
 * Data class representing the WebIDL AuthenticationExtensionsLargeBlobOutputs dictionary.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#dictdef-authenticationextensionslargebloboutputs">
 * §10.5. Large blob storage extension (largeBlob)</a>
 */
public class AuthenticationExtensionsLargeBlobOutputs {

    private final Boolean supported;
    private final byte[] blob;
    private final Boolean written;

    @JsonCreator
    public AuthenticationExtensionsLargeBlobOutputs(
            @Nullable @JsonProperty("supported") Boolean supported,
            @Nullable @JsonProperty("blob") byte[] blob,
            @Nullable @JsonProperty("written") Boolean written) {
        this.supported = supported;
        this.blob = ArrayUtil.clone(blob);
        this.written = written;
    }

    public @Nullable Boolean getSupported() {
        return supported;
    }

    public @Nullable byte[] getBlob() {
        return ArrayUtil.clone(blob);
    }

    public @Nullable Boolean getWritten() {
        return written;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AuthenticationExtensionsLargeBlobOutputs that = (AuthenticationExtensionsLargeBlobOutputs) o;
        return Objects.equals(supported, that.supported) && Arrays.equals(blob, that.blob) && Objects.equals(written, that.written);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(supported, written);
        result = 31 * result + Arrays.hashCode(blob);
        return result;
    }
}
