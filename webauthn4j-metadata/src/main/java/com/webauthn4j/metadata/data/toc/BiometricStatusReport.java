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

package com.webauthn4j.metadata.data.toc;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.math.BigInteger;
import java.util.Objects;

/**
 * Contains the current BiometricStatusReport of one of the authenticator's biometric component.
 */
public class BiometricStatusReport {
    @NonNull private final Integer certLevel;
    @NonNull private final BigInteger modality;
    @Nullable private final String effectiveData;
    @Nullable private final String certificationDescriptor;
    @Nullable private final String certificateNumber;
    @Nullable private final String certificationPolicyVersion;
    @Nullable private final String certificationRequirementsVersion;

    @JsonCreator
    public BiometricStatusReport(
            @JsonProperty("certLevel") @NonNull Integer certLevel,
            @JsonProperty("modality") @NonNull BigInteger modality,
            @JsonProperty("effectiveData") @Nullable String effectiveData,
            @JsonProperty("certificationDescriptor") @Nullable String certificationDescriptor,
            @JsonProperty("certificateNumber") @Nullable String certificateNumber,
            @JsonProperty("certificationPolicyVersion") @Nullable String certificationPolicyVersion,
            @JsonProperty("certificationRequirementsVersion") @Nullable String certificationRequirementsVersion) {
        this.certLevel = certLevel;
        this.modality = modality;
        this.effectiveData = effectiveData;
        this.certificationDescriptor = certificationDescriptor;
        this.certificateNumber = certificateNumber;
        this.certificationPolicyVersion = certificationPolicyVersion;
        this.certificationRequirementsVersion = certificationRequirementsVersion;
    }

    @NonNull
    public Integer getCertLevel() {
        return certLevel;
    }

    @NonNull
    public BigInteger getModality() {
        return modality;
    }

    @Nullable
    public String getEffectiveData() {
        return effectiveData;
    }

    @Nullable
    public String getCertificationDescriptor() {
        return certificationDescriptor;
    }

    @Nullable
    public String getCertificateNumber() {
        return certificateNumber;
    }

    @Nullable
    public String getCertificationPolicyVersion() {
        return certificationPolicyVersion;
    }

    @Nullable
    public String getCertificationRequirementsVersion() {
        return certificationRequirementsVersion;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BiometricStatusReport that = (BiometricStatusReport) o;
        return Objects.equals(certLevel, that.certLevel) &&
                Objects.equals(modality, that.modality) &&
                Objects.equals(effectiveData, that.effectiveData) &&
                Objects.equals(certificationDescriptor, that.certificationDescriptor) &&
                Objects.equals(certificateNumber, that.certificateNumber) &&
                Objects.equals(certificationPolicyVersion, that.certificationPolicyVersion) &&
                Objects.equals(certificationRequirementsVersion, that.certificationRequirementsVersion);
    }

    @Override
    public int hashCode() {

        return Objects.hash(certLevel, modality, effectiveData, certificationDescriptor, certificateNumber, certificationPolicyVersion, certificationRequirementsVersion);
    }
}
