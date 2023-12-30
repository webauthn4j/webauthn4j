package com.webauthn4j.data.attestation.statement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.checkerframework.checker.nullness.qual.NonNull;

import java.util.*;
import java.util.stream.Collectors;

@JsonIgnoreProperties(value = "format")
@JsonTypeName(CompoundAttestationStatement.FORMAT)
public class CompoundAttestationStatement extends AbstractList<CompoundAttestationStatementItem> implements AttestationStatement {

    private static final String ATTSTMT_MUST_NOT_BE_NULL = "attStmt must not be null";

    public static final String FORMAT = "compound";

    private final List<CompoundAttestationStatementItem> attStmt;


    public CompoundAttestationStatement(@NonNull CompoundAttestationStatementItem... attStmt) {
        AssertUtil.notNull(attStmt, ATTSTMT_MUST_NOT_BE_NULL);
        this.attStmt = Arrays.stream(attStmt).collect(Collectors.toList());
    }

    @JsonCreator
    public CompoundAttestationStatement(@NonNull List<CompoundAttestationStatementItem> attStmt) {
        AssertUtil.notNull(attStmt, ATTSTMT_MUST_NOT_BE_NULL);
        this.attStmt = new ArrayList<>(attStmt);
    }

    public CompoundAttestationStatement(@NonNull AttestationStatement... attStmt){
        AssertUtil.notNull(attStmt, ATTSTMT_MUST_NOT_BE_NULL);
        this.attStmt = Arrays.stream(attStmt).map(CompoundAttestationStatementItem::new).collect(Collectors.toList());
    }

    @Override
    public CompoundAttestationStatementItem get(int index) {
        return attStmt.get(index);
    }

    @Override
    public int size() {
        return attStmt.size();
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
            item.getAttestationStatement().validate();
        });
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        CompoundAttestationStatement that = (CompoundAttestationStatement) o;
        return Objects.equals(attStmt, that.attStmt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), attStmt);
    }

    @Override
    public String toString() {
        return attStmt.toString();
    }
}
