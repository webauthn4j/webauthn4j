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

import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.Objects;

/**
 * The PublicKeyCredentialEntity describes a user account, or a WebAuthn Relying Party,
 * which a public key credential is associated with or scoped to, respectively.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#dictionary-pkcredentialentity">
 * §5.4.1. Public Key Entity Description (dictionary PublicKeyCredentialEntity)</a>
 */
public abstract class PublicKeyCredentialEntity {

    // ~ Instance fields
    // ================================================================================================

    private final String name;

    // ~ Constructor
    // ========================================================================================================

    /**
     * @param name name
     */
    protected PublicKeyCredentialEntity(@NonNull String name) {
        AssertUtil.notNull(name, "name must not be null");
        this.name = name;
    }

    public @NonNull String getName() {
        return name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PublicKeyCredentialEntity that = (PublicKeyCredentialEntity) o;
        return Objects.equals(name, that.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name);
    }

    @Override
    public String toString() {
        return "PublicKeyCredentialEntity(" +
                "name=" + name +
                ')';
    }
}
