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
import org.checkerframework.checker.nullness.qual.Nullable;

import java.util.Objects;

/**
 * BiometricAccuracyDescriptor
 */
@SuppressWarnings("squid:S00116")
public class BiometricAccuracyDescriptor {

    @Nullable private final Double selfAttestedFAR;
    @Nullable private final Double selfAttestedFRR;
    @Nullable private final Integer maxTemplate;
    @Nullable private final Integer maxRetries;
    @Nullable private final Integer blockSlowdown;

    @JsonCreator
    public BiometricAccuracyDescriptor(
            @JsonProperty("selfAttestedFAR") @Nullable Double selfAttestedFAR,
            @JsonProperty("selfAttestedFRR") @Nullable Double selfAttestedFRR,
            @JsonProperty("maxTemplate") @Nullable Integer maxTemplate,
            @JsonProperty("maxRetries") @Nullable Integer maxRetries,
            @JsonProperty("blockSlowdown") @Nullable Integer blockSlowdown) {
        this.selfAttestedFAR = selfAttestedFAR;
        this.selfAttestedFRR = selfAttestedFRR;
        this.maxTemplate = maxTemplate;
        this.maxRetries = maxRetries;
        this.blockSlowdown = blockSlowdown;
    }

    @Nullable
    public Double getSelfAttestedFAR() {
        return selfAttestedFAR;
    }

    @Nullable
    public Double getSelfAttestedFRR() {
        return selfAttestedFRR;
    }

    @Nullable
    public Integer getMaxTemplate() {
        return maxTemplate;
    }

    @Nullable
    public Integer getMaxRetries() {
        return maxRetries;
    }

    @Nullable
    public Integer getBlockSlowdown() {
        return blockSlowdown;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BiometricAccuracyDescriptor that = (BiometricAccuracyDescriptor) o;
        return Objects.equals(selfAttestedFAR, that.selfAttestedFAR) && Objects.equals(selfAttestedFRR, that.selfAttestedFRR) && Objects.equals(maxTemplate, that.maxTemplate) && Objects.equals(maxRetries, that.maxRetries) && Objects.equals(blockSlowdown, that.blockSlowdown);
    }

    @Override
    public int hashCode() {
        return Objects.hash(selfAttestedFAR, selfAttestedFRR, maxTemplate, maxRetries, blockSlowdown);
    }
}
