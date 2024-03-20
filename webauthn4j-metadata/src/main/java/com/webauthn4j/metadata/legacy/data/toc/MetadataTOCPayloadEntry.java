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

package com.webauthn4j.metadata.legacy.data.toc;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateDeserializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateSerializer;
import com.webauthn4j.metadata.data.toc.BiometricStatusReport;
import com.webauthn4j.metadata.data.toc.StatusReport;
import com.webauthn4j.util.CollectionUtil;

import java.net.URI;
import java.time.LocalDate;
import java.util.List;
import java.util.Objects;

/**
 * Represents the MetadataTOCPayloadEntry
 */
@Deprecated
public class MetadataTOCPayloadEntry {

    @JsonProperty
    private final String aaid;
    @JsonProperty
    private final String aaguid;
    @JsonProperty
    private final List<String> attestationCertificateKeyIdentifiers;
    @JsonProperty
    private final String hash;
    @JsonProperty
    private final URI url;
    @JsonProperty
    private final List<BiometricStatusReport> biometricStatusReports;
    @JsonProperty
    private final List<StatusReport> statusReports;

    @JsonDeserialize(using = LocalDateDeserializer.class)
    @JsonSerialize(using = LocalDateSerializer.class)
    @JsonProperty
    private final LocalDate timeOfLastStatusChange;
    @JsonProperty
    private final String rogueListURL;
    @JsonProperty
    private final String rogueListHash;

    @JsonCreator
    public MetadataTOCPayloadEntry(
            @JsonProperty("aaid") String aaid,
            @JsonProperty("aaguid") String aaguid,
            @JsonProperty("attestationCertificateKeyIdentifiers") List<String> attestationCertificateKeyIdentifiers,
            @JsonProperty("hash") String hash,
            @JsonProperty("url") URI url,
            @JsonProperty("biometricStatusReports") List<BiometricStatusReport> biometricStatusReports,
            @JsonProperty("statusReports") List<StatusReport> statusReports,
            @JsonProperty("timeOfLastStatusChange") LocalDate timeOfLastStatusChange,
            @JsonProperty("rogueListURL") String rogueListURL,
            @JsonProperty("rogueListHash") String rogueListHash) {
        this.aaid = aaid;
        this.aaguid = aaguid;
        this.attestationCertificateKeyIdentifiers = CollectionUtil.unmodifiableList(attestationCertificateKeyIdentifiers);
        this.hash = hash;
        this.url = url;
        this.biometricStatusReports = CollectionUtil.unmodifiableList(biometricStatusReports);
        this.statusReports = CollectionUtil.unmodifiableList(statusReports);
        this.timeOfLastStatusChange = timeOfLastStatusChange;
        this.rogueListURL = rogueListURL;
        this.rogueListHash = rogueListHash;
    }

    public String getAaid() {
        return aaid;
    }

    public String getAaguid() {
        return aaguid;
    }

    public List<String> getAttestationCertificateKeyIdentifiers() {
        return attestationCertificateKeyIdentifiers;
    }

    public String getHash() {
        return hash;
    }

    public URI getUrl() {
        return url;
    }

    public List<BiometricStatusReport> getBiometricStatusReports() {
        return biometricStatusReports;
    }

    public List<StatusReport> getStatusReports() {
        return statusReports;
    }

    public LocalDate getTimeOfLastStatusChange() {
        return timeOfLastStatusChange;
    }

    public String getRogueListURL() {
        return rogueListURL;
    }

    public String getRogueListHash() {
        return rogueListHash;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        MetadataTOCPayloadEntry that = (MetadataTOCPayloadEntry) o;
        return Objects.equals(aaid, that.aaid) &&
                Objects.equals(aaguid, that.aaguid) &&
                Objects.equals(attestationCertificateKeyIdentifiers, that.attestationCertificateKeyIdentifiers) &&
                Objects.equals(hash, that.hash) &&
                Objects.equals(url, that.url) &&
                Objects.equals(biometricStatusReports, that.biometricStatusReports) &&
                Objects.equals(statusReports, that.statusReports) &&
                Objects.equals(timeOfLastStatusChange, that.timeOfLastStatusChange) &&
                Objects.equals(rogueListURL, that.rogueListURL) &&
                Objects.equals(rogueListHash, that.rogueListHash);
    }

    @Override
    public int hashCode() {

        return Objects.hash(aaid, aaguid, attestationCertificateKeyIdentifiers, hash, url, biometricStatusReports, statusReports, timeOfLastStatusChange, rogueListURL, rogueListHash);
    }
}
