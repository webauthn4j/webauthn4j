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

package com.webauthn4j.metadata.data;

import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.statement.MetadataStatement;
import com.webauthn4j.metadata.data.toc.StatusReport;
import com.webauthn4j.util.WIP;

import java.time.LocalDate;
import java.util.List;

/**
 * Created by ynojima on 2017/09/24.
 */
@WIP
public class MetadataItemImpl implements MetadataItem {

    private final String aaid;
    private final AAGUID aaguid;
    private final List<String> attestationCertificateKeyIdentifiers;
    private final String hash;
    private final List<StatusReport> statusReports;
    private final LocalDate timeOfLastStatusChange;
    private final MetadataStatement metadataStatement;

    public MetadataItemImpl(
            String aaid,
            AAGUID aaguid,
            List<String> attestationCertificateKeyIdentifiers,
            String hash,
            List<StatusReport> statusReports,
            LocalDate timeOfLastStatusChange,
            MetadataStatement metadataStatement) {
        this.aaid = aaid;
        this.aaguid = aaguid;
        this.attestationCertificateKeyIdentifiers = attestationCertificateKeyIdentifiers;
        this.hash = hash;
        this.statusReports = statusReports;
        this.timeOfLastStatusChange = timeOfLastStatusChange;
        this.metadataStatement = metadataStatement;
    }

    @Override
    public String getAaid() {
        return aaid;
    }

    @Override
    public AAGUID getAaguid() {
        return aaguid;
    }

    @Override
    public List<String> getAttestationCertificateKeyIdentifiers() {
        return attestationCertificateKeyIdentifiers;
    }

    @Override
    public String getHash() {
        return hash;
    }

    @Override
    public List<StatusReport> getStatusReports() {
        return statusReports;
    }

    @Override
    public LocalDate getTimeOfLastStatusChange() {
        return timeOfLastStatusChange;
    }

    @Override
    public MetadataStatement getMetadataStatement() {
        return metadataStatement;
    }
}
