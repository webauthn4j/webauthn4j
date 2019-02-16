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

package com.webauthn4j.metadata.data.toc;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Objects;

/**
 * Contains the current BiometricStatusReport of one of the authenticator's biometric component.
 */
public class BiometricStatusReport implements Serializable {
    private Integer certLevel;
    private BigInteger modality;
    private String effectiveData;
    private String certificationDescriptor;
    private String certificateNumber;
    private String certificationPolicyVersion;
    private String certificationRequirementsVersion;

    @JsonCreator
    public BiometricStatusReport(
            @JsonProperty("certLevel") Integer certLevel,
            @JsonProperty("modality") BigInteger modality,
            @JsonProperty("effectiveData") String effectiveData,
            @JsonProperty("certificationDescriptor") String certificationDescriptor,
            @JsonProperty("certificateNumber") String certificateNumber,
            @JsonProperty("certificationPolicyVersion") String certificationPolicyVersion,
            @JsonProperty("certificationRequirementsVersion") String certificationRequirementsVersion) {
        this.certLevel = certLevel;
        this.modality = modality;
        this.effectiveData = effectiveData;
        this.certificationDescriptor = certificationDescriptor;
        this.certificateNumber = certificateNumber;
        this.certificationPolicyVersion = certificationPolicyVersion;
        this.certificationRequirementsVersion = certificationRequirementsVersion;
    }

    public Integer getCertLevel() {
        return certLevel;
    }

    public BigInteger getModality() {
        return modality;
    }

    public String getEffectiveData() {
        return effectiveData;
    }

    public String getCertificationDescriptor() {
        return certificationDescriptor;
    }

    public String getCertificateNumber() {
        return certificateNumber;
    }

    public String getCertificationPolicyVersion() {
        return certificationPolicyVersion;
    }

    public String getCertificationRequirementsVersion() {
        return certificationRequirementsVersion;
    }

    @Override
    public boolean equals(Object o) {
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
