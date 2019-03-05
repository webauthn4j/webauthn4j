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

package com.webauthn4j.request;

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

    private String id;

    // ~ Constructor
    // ========================================================================================================

    public PublicKeyCredentialRpEntity(String id, String name, String icon) {
        super(name, icon);
        this.id = id;
    }

    public PublicKeyCredentialRpEntity(String id, String name) {
        super(name);
        this.id = id;
    }

    public PublicKeyCredentialRpEntity(String name) {
        super(name);
        this.id = null;
    }

    public String getId() {
        return id;
    }

    @Override
    public boolean equals(Object o) {
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
}
