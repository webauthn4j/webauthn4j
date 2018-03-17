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

package net.sharplab.springframework.security.fido.metadata;

import net.sharplab.springframework.security.fido.metadata.structure.MetadataStatement;
import net.sharplab.springframework.security.fido.metadata.structure.StatusReport;

import java.time.LocalDate;
import java.util.List;

/**
 * Created by ynojima on 2017/09/24.
 */
public class Metadata {

    private String aaid;
    private String hash;
    private List<StatusReport> statusReports;
    private LocalDate timeOfLastStatusChange;
    private List<String> attestationCertificateKeyIdentifiers;
    private MetadataStatement metadataStatement;

    public String getAaid() {
        return aaid;
    }

    public void setAaid(String aaid) {
        this.aaid = aaid;
    }

    public String getHash() {
        return hash;
    }

    public void setHash(String hash) {
        this.hash = hash;
    }

    public List<StatusReport> getStatusReports() {
        return statusReports;
    }

    public void setStatusReports(List<StatusReport> statusReports) {
        this.statusReports = statusReports;
    }

    public LocalDate getTimeOfLastStatusChange() {
        return timeOfLastStatusChange;
    }

    public void setTimeOfLastStatusChange(LocalDate timeOfLastStatusChange) {
        this.timeOfLastStatusChange = timeOfLastStatusChange;
    }

    public List<String> getAttestationCertificateKeyIdentifiers() {
        return attestationCertificateKeyIdentifiers;
    }

    public void setAttestationCertificateKeyIdentifiers(List<String> attestationCertificateKeyIdentifiers) {
        this.attestationCertificateKeyIdentifiers = attestationCertificateKeyIdentifiers;
    }

    public MetadataStatement getMetadataStatement() {
        return metadataStatement;
    }

    public void setMetadataStatement(MetadataStatement metadataStatement) {
        this.metadataStatement = metadataStatement;
    }
}
