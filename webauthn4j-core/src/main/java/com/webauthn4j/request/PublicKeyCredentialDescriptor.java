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

import com.webauthn4j.util.CollectionUtil;

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class PublicKeyCredentialDescriptor implements Serializable {

    // ~ Instance fields
    // ================================================================================================

    private PublicKeyCredentialType type;
    private byte[] id;
    private List<AuthenticatorTransport> transports;

    public PublicKeyCredentialDescriptor(PublicKeyCredentialType type, byte[] id, List<AuthenticatorTransport> transports) {
        this.type = type;
        this.id = id;
        this.transports = CollectionUtil.unmodifiableList(transports);
    }

    public PublicKeyCredentialType getType() {
        return type;
    }

    public byte[] getId() {
        return id.clone();
    }

    public List<AuthenticatorTransport> getTransports() {
        return transports;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PublicKeyCredentialDescriptor that = (PublicKeyCredentialDescriptor) o;
        return type == that.type &&
                Arrays.equals(id, that.id) &&
                Objects.equals(transports, that.transports);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(type, transports);
        result = 31 * result + Arrays.hashCode(id);
        return result;
    }
}
