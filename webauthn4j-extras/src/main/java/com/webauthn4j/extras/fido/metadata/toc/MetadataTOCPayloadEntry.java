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

package com.webauthn4j.extras.fido.metadata.toc;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateDeserializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateSerializer;
import com.webauthn4j.util.WIP;

import java.net.URI;
import java.time.LocalDate;
import java.util.List;

/**
 * Created by ynojima on 2017/09/08.
 */
@WIP
public class MetadataTOCPayloadEntry {

    @JsonProperty
    private String aaid;
    @JsonProperty
    private String aaguid;
    @JsonProperty
    private List<String> attestationCertificateKeyIdentifiers;
    @JsonProperty
    private String hash;
    @JsonProperty
    private URI url;
    @JsonProperty
    private List<BiometricStatusReport> biometricStatusReports;
    @JsonProperty
    private List<StatusReport> statusReports;

    @JsonDeserialize(using = LocalDateDeserializer.class)
    @JsonSerialize(using = LocalDateSerializer.class)
    @JsonProperty
    private LocalDate timeOfLastStatusChange;
    @JsonProperty
    private String rogueListURL;
    @JsonProperty
    private String rogueListHash;

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
}
