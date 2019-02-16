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

import java.util.Objects;

/**
 * BiometricAccuracyDescriptor
 */
@SuppressWarnings("squid:S00116")
public class BiometricAccuracyDescriptor {

    private double selfAttestedFAR;
    private double selfAttestedFRR;
    private Integer maxTemplate;
    private Integer maxRetries;
    private Integer blockSlowdown;

    @JsonCreator
    public BiometricAccuracyDescriptor(
            @JsonProperty("selfAttestedFAR") double selfAttestedFAR,
            @JsonProperty("selfAttestedFRR") double selfAttestedFRR,
            @JsonProperty("maxTemplate") Integer maxTemplate,
            @JsonProperty("maxRetries") Integer maxRetries,
            @JsonProperty("blockSlowdown") Integer blockSlowdown) {
        this.selfAttestedFAR = selfAttestedFAR;
        this.selfAttestedFRR = selfAttestedFRR;
        this.maxTemplate = maxTemplate;
        this.maxRetries = maxRetries;
        this.blockSlowdown = blockSlowdown;
    }

    public double getSelfAttestedFAR() {
        return selfAttestedFAR;
    }

    public double getSelfAttestedFRR() {
        return selfAttestedFRR;
    }

    public Integer getMaxTemplate() {
        return maxTemplate;
    }

    public Integer getMaxRetries() {
        return maxRetries;
    }

    public Integer getBlockSlowdown() {
        return blockSlowdown;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BiometricAccuracyDescriptor that = (BiometricAccuracyDescriptor) o;
        return Double.compare(that.selfAttestedFAR, selfAttestedFAR) == 0 &&
                Double.compare(that.selfAttestedFRR, selfAttestedFRR) == 0 &&
                Objects.equals(maxTemplate, that.maxTemplate) &&
                Objects.equals(maxRetries, that.maxRetries) &&
                Objects.equals(blockSlowdown, that.blockSlowdown);
    }

    @Override
    public int hashCode() {

        return Objects.hash(selfAttestedFAR, selfAttestedFRR, maxTemplate, maxRetries, blockSlowdown);
    }
}
