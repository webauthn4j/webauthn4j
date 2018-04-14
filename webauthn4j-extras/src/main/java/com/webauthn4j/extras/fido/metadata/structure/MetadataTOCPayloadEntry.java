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

package com.webauthn4j.extras.fido.metadata.structure;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.net.URI;
import java.time.LocalDate;
import java.util.List;

/**
 * Created by ynojima on 2017/09/08.
 */
public class MetadataTOCPayloadEntry {

    @JsonProperty
    private String aaid;
    @JsonProperty
    private String hash;
    @JsonProperty
    private URI url;
    @JsonProperty
    private List<StatusReport> statusReports;
    @JsonProperty
    private LocalDate timeOfLastStatusChange;
    @JsonProperty
    private List<String> attestationCertificateKeyIdentifiers;

    public String getAaid() {
        return aaid;
    }

    public String getHash() {
        return hash;
    }

    public URI getUrl() {
        return url;
    }

    public List<StatusReport> getStatusReports() {
        return statusReports;
    }

    public LocalDate getTimeOfLastStatusChange() {
        return timeOfLastStatusChange;
    }

    public List<String> getAttestationCertificateKeyIdentifiers() {
        return attestationCertificateKeyIdentifiers;
    }
}
