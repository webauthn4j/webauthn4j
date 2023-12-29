package com.webauthn4j.data.attestation.statement;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@JsonIgnoreProperties(value = "format")
@JsonTypeName(CompoundAttestationStatement.FORMAT)
public class CompoundAttestationStatement implements AttestationStatement {

    public static final String FORMAT = "compound";

    @JsonProperty("attStmt")
    private final List<AttestationStatement> attStmt;


    public CompoundAttestationStatement(@NonNull @JsonProperty("attStmt") List<AttestationStatement> attStmt) {
        AssertUtil.notNull(attStmt, "attStmt must not be null");
        this.attStmt = attStmt;
    }

    public CompoundAttestationStatement(@NonNull @JsonProperty("attStmt") AttestationStatement... attStmt) {
        AssertUtil.notNull(attStmt, "attStmt must not be null");
        this.attStmt = Arrays.stream(attStmt).collect(Collectors.toList());
    }

    public List<AttestationStatement> getAttStmt() {
        return attStmt;
    }


    @Override
    public @NonNull String getFormat() {
        return FORMAT;
    }

    @Override
    public void validate() {
        if (attStmt.size() < 2) {
            throw new ConstraintViolationException("attStmt must have at least 2 items.");
        }
        attStmt.forEach(item ->{
            if(FORMAT.equals(item.getFormat())){
                throw new ConstraintViolationException("attStmt must not contain compound attestation statement.");
            }
            item.validate();
        });
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CompoundAttestationStatement that = (CompoundAttestationStatement) o;
        return Objects.equals(attStmt, that.attStmt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(attStmt);
    }

    @Override
    public String toString() {
        return "CompoundAttestationStatement(" +
                "attStmt=" + attStmt +
                ')';
    }
}
