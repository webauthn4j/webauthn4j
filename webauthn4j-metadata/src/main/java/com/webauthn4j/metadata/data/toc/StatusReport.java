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
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateDeserializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateSerializer;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.util.Objects;

/**
 * Contains an AuthenticatorStatus and additional data associated with it, if any.
 * New StatusReport entries will be added to report known issues present in firmware updates.
 */
public class StatusReport {
    @NonNull
    @JsonProperty
    private final AuthenticatorStatus status;

    @Nullable
    @JsonDeserialize(using = LocalDateDeserializer.class)
    @JsonSerialize(using = LocalDateSerializer.class)
    @JsonProperty
    private final LocalDate effectiveDate;

    @Nullable
    @JsonProperty
    private final X509Certificate certificate;

    @Nullable
    @JsonProperty
    private final String url;

    @Nullable
    @JsonProperty
    private final String certificationDescriptor;

    @Nullable
    @JsonProperty
    private final String certificateNumber;

    @Nullable
    @JsonProperty
    private final String certificationPolicyVersion;;

    @Nullable
    @JsonProperty
    private final String certificationRequirementsVersion;


    @JsonCreator
    public StatusReport(
            @JsonProperty("status") @NonNull AuthenticatorStatus status,
            @JsonProperty("effectiveDate") @Nullable LocalDate effectiveDate,
            @JsonProperty("certificate") @Nullable X509Certificate certificate,
            @JsonProperty("url") @Nullable String url,
            @JsonProperty("certificationDescriptor") @Nullable String certificationDescriptor,
            @JsonProperty("certificateNumber") @Nullable String certificateNumber,
            @JsonProperty("certificationPolicyVersion") @Nullable String certificationPolicyVersion,
            @JsonProperty("certificationRequirementsVersion") @Nullable String certificationRequirementsVersion) {
        this.status = status;
        this.effectiveDate = effectiveDate;
        this.certificate = certificate;
        this.url = url;
        this.certificationDescriptor = certificationDescriptor;
        this.certificateNumber = certificateNumber;
        this.certificationPolicyVersion = certificationPolicyVersion;
        this.certificationRequirementsVersion = certificationRequirementsVersion;
    }

    @NonNull
    public AuthenticatorStatus getStatus() {
        return status;
    }

    @Nullable
    public LocalDate getEffectiveDate() {
        return effectiveDate;
    }

    @Nullable
    public X509Certificate getCertificate() {
        return certificate;
    }

    @Nullable
    public String getUrl() {
        return url;
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
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        StatusReport that = (StatusReport) o;
        return status == that.status && Objects.equals(effectiveDate, that.effectiveDate) && Objects.equals(certificate, that.certificate) && Objects.equals(url, that.url) && Objects.equals(certificationDescriptor, that.certificationDescriptor) && Objects.equals(certificateNumber, that.certificateNumber) && Objects.equals(certificationPolicyVersion, that.certificationPolicyVersion) && Objects.equals(certificationRequirementsVersion, that.certificationRequirementsVersion);
    }

    @Override
    public int hashCode() {
        return Objects.hash(status, effectiveDate, certificate, url, certificationDescriptor, certificateNumber, certificationPolicyVersion, certificationRequirementsVersion);
    }
}
