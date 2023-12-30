package com.webauthn4j.data.attestation.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.webauthn4j.util.AssertUtil;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.io.Serializable;
import java.util.Objects;

public class CompoundAttestationStatementItem implements Serializable {
    @JsonProperty("attStmt")
    @JsonTypeInfo(
            use = JsonTypeInfo.Id.NAME,
            include = JsonTypeInfo.As.EXTERNAL_PROPERTY,
            property = "fmt"
    )
    private final AttestationStatement attestationStatement;

    @JsonCreator
    public CompoundAttestationStatementItem(
            @NonNull @JsonProperty("attStmt") AttestationStatement attestationStatement) {
        AssertUtil.notNull(attestationStatement, "attestationStatement must not be null");
        this.attestationStatement = attestationStatement;
    }

    @JsonProperty("fmt")
    public @NonNull String getFormat() {
        return attestationStatement.getFormat();
    }

    public @NonNull AttestationStatement getAttestationStatement() {
        return attestationStatement;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CompoundAttestationStatementItem that = (CompoundAttestationStatementItem) o;
        return Objects.equals(attestationStatement, that.attestationStatement);
    }

    @Override
    public int hashCode() {
        return Objects.hash(attestationStatement);
    }

    @Override
    public String toString() {
        return "CompoundAttestationStatementItem(" +
                "attestationStatement=" + attestationStatement +
                ')';
    }
}
