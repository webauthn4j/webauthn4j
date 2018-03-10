package net.sharplab.springframework.security.fido.metadata.structure;

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
