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
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import tools.jackson.databind.annotation.JsonDeserialize;
import tools.jackson.databind.annotation.JsonSerialize;
import tools.jackson.databind.ext.javatime.deser.LocalDateDeserializer;
import tools.jackson.databind.ext.javatime.ser.LocalDateSerializer;

import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.util.List;
import java.util.Objects;

/**
 * Contains an {@link AuthenticatorStatus} and additional data associated with it, if any.
 *
 * @see <a href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#dictdef-statusreport">
 * §3.1.3. StatusReport dictionary</a>
 */
public class StatusReport {
    @NotNull
    @JsonProperty
    private final AuthenticatorStatus status;

    @Nullable
    @JsonDeserialize(using = LocalDateDeserializer.class)
    @JsonSerialize(using = LocalDateSerializer.class)
    @JsonProperty
    private final LocalDate effectiveDate;

    @Nullable
    @JsonProperty
    private final Long authenticatorVersion;

    @Nullable
    @JsonProperty
    private final X509Certificate batchCertificate;

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
    private final String certificationPolicyVersion;

    @Nullable
    @JsonProperty
    private final List<CertificationProfile> certificationProfiles;

    @Nullable
    @JsonProperty
    private final String certificationRequirementsVersion;

    @Nullable
    @JsonDeserialize(using = LocalDateDeserializer.class)
    @JsonSerialize(using = LocalDateSerializer.class)
    @JsonProperty
    private final LocalDate sunsetDate;

    @Nullable
    @JsonProperty
    private final Long fipsRevision;

    @Nullable
    @JsonProperty
    private final Long fipsPhysicalSecurityLevel;

    @SuppressWarnings("java:S107")
    @JsonCreator
    public StatusReport(
            @JsonProperty("status") @NotNull AuthenticatorStatus status,
            @JsonProperty("effectiveDate") @Nullable LocalDate effectiveDate,
            @JsonProperty("authenticatorVersion") @Nullable Long authenticatorVersion,
            @JsonProperty("certificate") @Nullable X509Certificate certificate,
            @JsonProperty("batchCertificate") @Nullable X509Certificate batchCertificate,
            @JsonProperty("url") @Nullable String url,
            @JsonProperty("certificationDescriptor") @Nullable String certificationDescriptor,
            @JsonProperty("certificateNumber") @Nullable String certificateNumber,
            @JsonProperty("certificationPolicyVersion") @Nullable String certificationPolicyVersion,
            @JsonProperty("certificationProfiles") @Nullable List<CertificationProfile> certificationProfiles,
            @JsonProperty("certificationRequirementsVersion") @Nullable String certificationRequirementsVersion,
            @JsonProperty("sunsetDate") @Nullable LocalDate sunsetDate,
            @JsonProperty("fipsRevision") @Nullable Long fipsRevision,
            @JsonProperty("fipsPhysicalSecurityLevel") @Nullable Long fipsPhysicalSecurityLevel) {
        this.status = status;
        this.effectiveDate = effectiveDate;
        this.authenticatorVersion = authenticatorVersion;
        this.certificate = certificate;
        this.batchCertificate = batchCertificate;
        this.url = url;
        this.certificationDescriptor = certificationDescriptor;
        this.certificateNumber = certificateNumber;
        this.certificationPolicyVersion = certificationPolicyVersion;
        this.certificationProfiles = certificationProfiles;
        this.certificationRequirementsVersion = certificationRequirementsVersion;
        this.sunsetDate = sunsetDate;
        this.fipsRevision = fipsRevision;
        this.fipsPhysicalSecurityLevel = fipsPhysicalSecurityLevel;
    }

    @Deprecated
    public StatusReport(
            @NotNull AuthenticatorStatus status,
            @Nullable LocalDate effectiveDate,
            @Nullable X509Certificate certificate,
            @Nullable String url,
            @Nullable String certificationDescriptor,
            @Nullable String certificateNumber,
            @Nullable String certificationPolicyVersion,
            @Nullable String certificationRequirementsVersion) {
        this(status, effectiveDate, null, certificate, null, url, certificationDescriptor,
                certificateNumber, certificationPolicyVersion, null, certificationRequirementsVersion,
                null, null, null);
    }

    @NotNull
    public AuthenticatorStatus getStatus() {
        return status;
    }

    @Nullable
    public LocalDate getEffectiveDate() {
        return effectiveDate;
    }

    @Nullable
    public Long getAuthenticatorVersion() {
        return authenticatorVersion;
    }

    @Nullable
    public X509Certificate getBatchCertificate() {
        return batchCertificate;
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
    public List<CertificationProfile> getCertificationProfiles() {
        return certificationProfiles;
    }

    @Nullable
    public String getCertificationRequirementsVersion() {
        return certificationRequirementsVersion;
    }

    @Nullable
    public LocalDate getSunsetDate() {
        return sunsetDate;
    }

    @Nullable
    public Long getFipsRevision() {
        return fipsRevision;
    }

    @Nullable
    public Long getFipsPhysicalSecurityLevel() {
        return fipsPhysicalSecurityLevel;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        StatusReport that = (StatusReport) o;
        return status == that.status && Objects.equals(effectiveDate, that.effectiveDate) && Objects.equals(authenticatorVersion, that.authenticatorVersion) && Objects.equals(certificate, that.certificate) && Objects.equals(batchCertificate, that.batchCertificate) && Objects.equals(url, that.url) && Objects.equals(certificationDescriptor, that.certificationDescriptor) && Objects.equals(certificateNumber, that.certificateNumber) && Objects.equals(certificationPolicyVersion, that.certificationPolicyVersion) && Objects.equals(certificationProfiles, that.certificationProfiles) && Objects.equals(certificationRequirementsVersion, that.certificationRequirementsVersion) && Objects.equals(sunsetDate, that.sunsetDate) && Objects.equals(fipsRevision, that.fipsRevision) && Objects.equals(fipsPhysicalSecurityLevel, that.fipsPhysicalSecurityLevel);
    }

    @Override
    public int hashCode() {
        return Objects.hash(status, effectiveDate, authenticatorVersion, certificate, batchCertificate, url, certificationDescriptor, certificateNumber, certificationPolicyVersion, certificationProfiles, certificationRequirementsVersion, sunsetDate, fipsRevision, fipsPhysicalSecurityLevel);
    }
}
