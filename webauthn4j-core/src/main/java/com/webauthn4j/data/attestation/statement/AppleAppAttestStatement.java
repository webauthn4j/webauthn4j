package com.webauthn4j.data.attestation.statement;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.webauthn4j.util.ArrayUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;

import java.util.Arrays;
import java.util.Objects;

@JsonIgnoreProperties(value = "format")
@JsonTypeName(AppleAppAttestStatement.FORMAT)
public class AppleAppAttestStatement implements CertificateBaseAttestationStatement {
    public static final String FORMAT = "apple-appattest";

    @JsonProperty
    private final AttestationCertificatePath x5c;

    @JsonProperty
    private final byte[] receipt;

    public AppleAppAttestStatement(
            @JsonProperty("x5c") AttestationCertificatePath x5c,
            @JsonProperty("receipt") byte[] receipt) {
        this.x5c = x5c;
        this.receipt = receipt;
    }

    public byte[] getReceipt() {
        return ArrayUtil.clone(receipt);
    }

    @Override
    public AttestationCertificatePath getX5c() {
        return x5c;
    }

    @Override
    public String getFormat() {
        return FORMAT;
    }

    @Override
    public void validate() {
        if (x5c == null) {
            throw new ConstraintViolationException("x5c must not be null");
        }
        if (receipt == null) {
            throw new ConstraintViolationException("receipt must not be null");
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AppleAppAttestStatement that = (AppleAppAttestStatement) o;
        return x5c.equals(that.x5c) &&
                Arrays.equals(receipt, that.receipt);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(x5c);
        result = 31 * result + Arrays.hashCode(receipt);
        return result;
    }
}
