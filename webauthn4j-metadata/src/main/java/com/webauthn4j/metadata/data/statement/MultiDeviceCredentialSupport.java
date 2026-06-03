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

package com.webauthn4j.metadata.data.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import org.jetbrains.annotations.NotNull;

import java.util.Objects;

/**
 * Indicates whether the authenticator supports multi-device credentials.
 *
 * @see <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1.1-rd-20251016.html#dom-metadatastatement-multidevicecredentialsupport">
 * §4. MetadataStatement - multiDeviceCredentialSupport</a>
 */
public class MultiDeviceCredentialSupport {

    public static final MultiDeviceCredentialSupport UNSUPPORTED = new MultiDeviceCredentialSupport("unsupported");
    public static final MultiDeviceCredentialSupport EXPLICIT = new MultiDeviceCredentialSupport("explicit");
    public static final MultiDeviceCredentialSupport IMPLICIT = new MultiDeviceCredentialSupport("implicit");

    @NotNull
    private final String value;

    @JsonCreator
    public MultiDeviceCredentialSupport(@NotNull String value) {
        this.value = value;
    }

    @JsonValue
    @NotNull
    public String getValue() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MultiDeviceCredentialSupport that = (MultiDeviceCredentialSupport) o;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return value;
    }
}
