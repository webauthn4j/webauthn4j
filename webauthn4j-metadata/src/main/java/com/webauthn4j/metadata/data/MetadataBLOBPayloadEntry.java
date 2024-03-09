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

package com.webauthn4j.metadata.data;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateDeserializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateSerializer;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.metadata.data.statement.MetadataStatement;
import com.webauthn4j.metadata.data.toc.BiometricStatusReport;
import com.webauthn4j.metadata.data.toc.StatusReport;
import com.webauthn4j.metadata.data.uaf.AAID;
import org.checkerframework.checker.nullness.qual.NonNull;
import org.checkerframework.checker.nullness.qual.Nullable;

import java.time.LocalDate;
import java.util.List;
import java.util.Objects;

public class MetadataBLOBPayloadEntry {

    @Nullable
    private final AAID aaid;
    @Nullable
    private final AAGUID aaguid;
    @Nullable
    private final List<String> attestationCertificateKeyIdentifiers;
    @Nullable
    private final MetadataStatement metadataStatement;
    @Nullable
    private final List<BiometricStatusReport> biometricStatusReports;
    @NonNull
    private final List<StatusReport> statusReports;

    @JsonDeserialize(using = LocalDateDeserializer.class)
    @JsonSerialize(using = LocalDateSerializer.class)
    @NonNull
    private final LocalDate timeOfLastStatusChange;
    @Nullable
    private final String rogueListURL;
    @Nullable
    private final String rogueListHash;

    public MetadataBLOBPayloadEntry(
            @JsonProperty("aaid") @Nullable AAID aaid,
            @JsonProperty("aaguid") @Nullable AAGUID aaguid,
            @JsonProperty("attestationCertificateKeyIdentifiers") @Nullable List<String> attestationCertificateKeyIdentifiers,
            @JsonProperty("metadataStatement") @Nullable MetadataStatement metadataStatement,
            @JsonProperty("biometricStatusReports") @Nullable List<BiometricStatusReport> biometricStatusReports,
            @JsonProperty("statusReports") @NonNull List<StatusReport> statusReports,
            @JsonProperty("timeOfLastStatusChange") @NonNull LocalDate timeOfLastStatusChange,
            @JsonProperty("rogueListURL") @Nullable String rogueListURL,
            @JsonProperty("rogueListHash") @Nullable String rogueListHash) {
        this.aaid = aaid;
        this.aaguid = aaguid;
        this.attestationCertificateKeyIdentifiers = attestationCertificateKeyIdentifiers;
        this.metadataStatement = metadataStatement;
        this.biometricStatusReports = biometricStatusReports;
        this.statusReports = statusReports;
        this.timeOfLastStatusChange = timeOfLastStatusChange;
        this.rogueListURL = rogueListURL;
        this.rogueListHash = rogueListHash;
    }

    @Nullable
    public AAID getAaid() {
        return aaid;
    }

    @Nullable
    public AAGUID getAaguid() {
        return aaguid;
    }

    @Nullable
    public List<String> getAttestationCertificateKeyIdentifiers() {
        return attestationCertificateKeyIdentifiers;
    }

    @Nullable
    public MetadataStatement getMetadataStatement() {
        return metadataStatement;
    }

    @Nullable
    public List<BiometricStatusReport> getBiometricStatusReports() {
        return biometricStatusReports;
    }

    @NonNull
    public List<StatusReport> getStatusReports() {
        return statusReports;
    }

    @NonNull
    public LocalDate getTimeOfLastStatusChange() {
        return timeOfLastStatusChange;
    }

    @Nullable
    public String getRogueListURL() {
        return rogueListURL;
    }

    @Nullable
    public String getRogueListHash() {
        return rogueListHash;
    }

    @Override
    public boolean equals(@Nullable Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MetadataBLOBPayloadEntry that = (MetadataBLOBPayloadEntry) o;
        return Objects.equals(aaid, that.aaid) && Objects.equals(aaguid, that.aaguid) && Objects.equals(attestationCertificateKeyIdentifiers, that.attestationCertificateKeyIdentifiers) && Objects.equals(metadataStatement, that.metadataStatement) && Objects.equals(biometricStatusReports, that.biometricStatusReports) && statusReports.equals(that.statusReports) && timeOfLastStatusChange.equals(that.timeOfLastStatusChange) && Objects.equals(rogueListURL, that.rogueListURL) && Objects.equals(rogueListHash, that.rogueListHash);
    }

    @Override
    public int hashCode() {
        return Objects.hash(aaid, aaguid, attestationCertificateKeyIdentifiers, metadataStatement, biometricStatusReports, statusReports, timeOfLastStatusChange, rogueListURL, rogueListHash);
    }
}
