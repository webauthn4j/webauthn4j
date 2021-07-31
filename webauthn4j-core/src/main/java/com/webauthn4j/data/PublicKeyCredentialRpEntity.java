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
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Objects;

/**
 * {@link PublicKeyCredentialRpEntity} is used to supply additional Relying Party attributes
 * when creating a new credential.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#dictdef-publickeycredentialrpentity">
 * §5.4.2. Relying Party Parameters for Credential Generation (dictionary PublicKeyCredentialRpEntity)</a>
 */
public class PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity {

    // ~ Instance fields
    // ================================================================================================

    private final String id;

    // ~ Constructor
    // ========================================================================================================

    /**
     * @param id   id
     * @param name name
     */
    @JsonCreator
    public PublicKeyCredentialRpEntity(
            @Nullable @JsonProperty("id") String id,
            @NonNull @JsonProperty("name") String name) {
        super(name);
        this.id = id;
    }

    public PublicKeyCredentialRpEntity(@NonNull String name) {
        super(name);
        this.id = null;
    }

    public @Nullable String getId() {
        return id;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        PublicKeyCredentialRpEntity that = (PublicKeyCredentialRpEntity) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {

        return Objects.hash(super.hashCode(), id);
    }

    @Override
    public String toString() {
        return "PublicKeyCredentialRpEntity(" +
                "id=" + id+
                "name=" + getName() +
                ')';
    }
}
