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
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.webauthn4j.converter.jackson.deserializer.json.UserVerificationMethodFromStringDeserializer;
import com.webauthn4j.converter.jackson.serializer.json.UserVerificationMethodToStringSerializer;
import com.webauthn4j.data.UserVerificationMethod;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Objects;

/**
 * A descriptor for a specific base user verification method as implemented by the authenticator.
 */
public class VerificationMethodDescriptor {

    @Nullable
    @JsonSerialize(using = UserVerificationMethodToStringSerializer.class)
    @JsonDeserialize(using = UserVerificationMethodFromStringDeserializer.class)
    private final UserVerificationMethod userVerificationMethod;
    @Nullable
    private final CodeAccuracyDescriptor caDesc;
    @Nullable
    private final BiometricAccuracyDescriptor baDesc;
    @Nullable
    private final PatternAccuracyDescriptor paDesc;

    @JsonCreator
    public VerificationMethodDescriptor(
            @JsonProperty("userVerificationMethod") @Nullable UserVerificationMethod userVerificationMethod,
            @JsonProperty("caDesc") @Nullable CodeAccuracyDescriptor caDesc,
            @JsonProperty("baDesc") @Nullable BiometricAccuracyDescriptor baDesc,
            @JsonProperty("paDesc") @Nullable PatternAccuracyDescriptor paDesc) {
        this.userVerificationMethod = userVerificationMethod;
        this.caDesc = caDesc;
        this.baDesc = baDesc;
        this.paDesc = paDesc;
    }

    @Nullable
    public UserVerificationMethod getUserVerificationMethod() {
        return userVerificationMethod;
    }

    @Nullable
    public CodeAccuracyDescriptor getCaDesc() {
        return caDesc;
    }

    @Nullable
    public BiometricAccuracyDescriptor getBaDesc() {
        return baDesc;
    }

    @Nullable
    public PatternAccuracyDescriptor getPaDesc() {
        return paDesc;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        VerificationMethodDescriptor that = (VerificationMethodDescriptor) o;
        return userVerificationMethod == that.userVerificationMethod && Objects.equals(caDesc, that.caDesc) && Objects.equals(baDesc, that.baDesc) && Objects.equals(paDesc, that.paDesc);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userVerificationMethod, caDesc, baDesc, paDesc);
    }
}
