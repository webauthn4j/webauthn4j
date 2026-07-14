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

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.jetbrains.annotations.Nullable;

import java.util.Objects;

/**
 * Describes the relevant accuracy/complexity aspects of an authenticator's biometric user verification methods.
 *
 * @see <a href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.1.1-ps-20260105.html#dictdef-biometricaccuracydescriptor">
 * §3.3. BiometricAccuracyDescriptor dictionary</a>
 */
@SuppressWarnings("squid:S00116")
public class BiometricAccuracyDescriptor {

    @Nullable private final Double selfAttestedFRR;
    @Nullable private final Double selfAttestedFAR;
    @Nullable private final Double iAPARThreshold;
    @Nullable private final Integer maxTemplates;
    @Nullable private final Integer maxRetries;
    @Nullable private final Integer blockSlowdown;

    @JsonCreator
    public BiometricAccuracyDescriptor(
            @JsonProperty("selfAttestedFRR") @Nullable Double selfAttestedFRR,
            @JsonProperty("selfAttestedFAR") @Nullable Double selfAttestedFAR,
            @JsonProperty("iAPARThreshold") @Nullable Double iAPARThreshold,
            @JsonProperty("maxTemplates") @JsonAlias("maxTemplate") @Nullable Integer maxTemplates,
            @JsonProperty("maxRetries") @Nullable Integer maxRetries,
            @JsonProperty("blockSlowdown") @Nullable Integer blockSlowdown) {
        this.selfAttestedFRR = selfAttestedFRR;
        this.selfAttestedFAR = selfAttestedFAR;
        this.iAPARThreshold = iAPARThreshold;
        this.maxTemplates = maxTemplates;
        this.maxRetries = maxRetries;
        this.blockSlowdown = blockSlowdown;
    }

    /**
     * @deprecated Use the full constructor instead.
     */
    @Deprecated
    public BiometricAccuracyDescriptor(
            @Nullable Double selfAttestedFAR,
            @Nullable Double selfAttestedFRR,
            @Nullable Integer maxTemplates,
            @Nullable Integer maxRetries,
            @Nullable Integer blockSlowdown) {
        this(selfAttestedFRR, selfAttestedFAR, null, maxTemplates, maxRetries, blockSlowdown);
    }

    @Nullable
    public Double getSelfAttestedFRR() {
        return selfAttestedFRR;
    }

    @Nullable
    public Double getSelfAttestedFAR() {
        return selfAttestedFAR;
    }

    @Nullable
    public Double getIAPARThreshold() {
        return iAPARThreshold;
    }

    @Nullable
    public Integer getMaxTemplates() {
        return maxTemplates;
    }

    /**
     * @deprecated Incorrectly named due to a typo; the spec field has always been "maxTemplates" (plural).
     * Use {@link #getMaxTemplates()} instead. This method will be removed in a future release.
     */
    @Deprecated
    @Nullable
    public Integer getMaxTemplate() {
        return getMaxTemplates();
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
        return Objects.equals(selfAttestedFRR, that.selfAttestedFRR) && Objects.equals(selfAttestedFAR, that.selfAttestedFAR) && Objects.equals(iAPARThreshold, that.iAPARThreshold) && Objects.equals(maxTemplates, that.maxTemplates) && Objects.equals(maxRetries, that.maxRetries) && Objects.equals(blockSlowdown, that.blockSlowdown);
    }

    @Override
    public int hashCode() {
        return Objects.hash(selfAttestedFRR, selfAttestedFAR, iAPARThreshold, maxTemplates, maxRetries, blockSlowdown);
    }
}
