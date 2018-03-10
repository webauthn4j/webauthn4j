package net.sharplab.springframework.security.fido.metadata.structure;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.security.cert.X509Certificate;
import java.time.LocalDate;

/**
 * Created by ynojima on 2017/09/08.
 */
public class StatusReport {
    @JsonProperty
    private AuthenticatorStatus status;
    @JsonProperty
    private LocalDate effectiveDate;
    @JsonProperty
    private X509Certificate certificate;
    @JsonProperty
    private String url;

    public AuthenticatorStatus getStatus() {
        return status;
    }

    public LocalDate getEffectiveDate() {
        return effectiveDate;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public String getUrl() {
        return url;
    }
}
