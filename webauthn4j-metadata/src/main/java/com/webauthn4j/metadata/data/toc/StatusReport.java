/*
 * Copyright 2018 the original author or authors.
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

package com.webauthn4j.metadata.data.toc;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateDeserializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateSerializer;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.util.Objects;

/**
 * Contains an AuthenticatorStatus and additional data associated with it, if any.
 * New StatusReport entries will be added to report known issues present in firmware updates.
 */
public class StatusReport implements Serializable {
    @JsonProperty
    private AuthenticatorStatus status;

    @JsonDeserialize(using = LocalDateDeserializer.class)
    @JsonSerialize(using = LocalDateSerializer.class)
    @JsonProperty
    private LocalDate effectiveDate;
    @JsonProperty
    private X509Certificate certificate;
    @JsonProperty
    private String url;

    @JsonCreator
    public StatusReport(
            @JsonProperty("status") AuthenticatorStatus status,
            @JsonProperty("effectiveDate") LocalDate effectiveDate,
            @JsonProperty("certificate") X509Certificate certificate,
            @JsonProperty("url") String url) {
        this.status = status;
        this.effectiveDate = effectiveDate;
        this.certificate = certificate;
        this.url = url;
    }

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

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        StatusReport that = (StatusReport) o;
        return status == that.status &&
                Objects.equals(effectiveDate, that.effectiveDate) &&
                Objects.equals(certificate, that.certificate) &&
                Objects.equals(url, that.url);
    }

    @Override
    public int hashCode() {

        return Objects.hash(status, effectiveDate, certificate, url);
    }
}
