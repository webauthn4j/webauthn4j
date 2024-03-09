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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.CollectionUtil;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Arrays;
import java.util.Objects;
import java.util.Set;

/**
 * {@link PublicKeyCredentialDescriptor} contains the attributes that are specified by a caller when referring to
 * a public key credential as an input parameter to the create() or get() methods.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#dictdef-publickeycredentialdescriptor">
 * §5.10.3. Credential Descriptor (dictionary PublicKeyCredentialDescriptor)</a>
 */
public class PublicKeyCredentialDescriptor {

    // ~ Instance fields
    // ================================================================================================

    private final PublicKeyCredentialType type;
    private final byte[] id;
    private final Set<AuthenticatorTransport> transports;

    @JsonCreator
    public PublicKeyCredentialDescriptor(
            @NonNull @JsonProperty("type") PublicKeyCredentialType type,
            @NonNull @JsonProperty("id") byte[] id,
            @Nullable @JsonProperty("transports") Set<AuthenticatorTransport> transports) {
        AssertUtil.notNull(type, "type must not be null");
        AssertUtil.notNull(id, "id must not be null");
        this.type = type;
        this.id = ArrayUtil.clone(id);
        this.transports = CollectionUtil.unmodifiableSet(transports);
    }

    public PublicKeyCredentialType getType() {
        return type;
    }

    public byte[] getId() {
        return ArrayUtil.clone(id);
    }

    public Set<AuthenticatorTransport> getTransports() {
        return transports;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PublicKeyCredentialDescriptor that = (PublicKeyCredentialDescriptor) o;
        return Objects.equals(type, that.type) && Arrays.equals(id, that.id) && Objects.equals(transports, that.transports);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(type, transports);
        result = 31 * result + Arrays.hashCode(id);
        return result;
    }

    @Override
    public String toString() {
        return "PublicKeyCredentialDescriptor(" +
                "type=" + type +
                ", id=" + ArrayUtil.toHexString(id) +
                ", transports=" + transports +
                ')';
    }
}
