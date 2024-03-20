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
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.Objects;

/**
 * {@link PublicKeyCredentialParameters} is used to supply additional parameters when creating a new credential.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-1/#dictdef-publickeycredentialparameters">
 * §5.3. Parameters for Credential Generation (dictionary PublicKeyCredentialParameters)</a>
 */
public class PublicKeyCredentialParameters {

    // ~ Instance fields
    // ================================================================================================

    private final PublicKeyCredentialType type;
    private final COSEAlgorithmIdentifier alg;

    @JsonCreator
    public PublicKeyCredentialParameters(
            @NonNull @JsonProperty("type") PublicKeyCredentialType type,
            @NonNull @JsonProperty("alg") COSEAlgorithmIdentifier alg) {
        AssertUtil.notNull(type, "type must not be null");
        AssertUtil.notNull(alg, "alg must not be null");
        this.type = type;
        this.alg = alg;
    }

    public @NonNull PublicKeyCredentialType getType() {
        return type;
    }

    public @NonNull COSEAlgorithmIdentifier getAlg() {
        return alg;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PublicKeyCredentialParameters that = (PublicKeyCredentialParameters) o;
        return Objects.equals(type, that.type) && Objects.equals(alg, that.alg);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, alg);
    }

    @Override
    public String toString() {
        return "PublicKeyCredentialParameters(" +
                "type=" + type +
                ", alg=" + alg +
                ')';
    }
}
