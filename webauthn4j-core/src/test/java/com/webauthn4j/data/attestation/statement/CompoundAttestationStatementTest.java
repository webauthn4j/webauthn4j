package com.webauthn4j.data.attestation.statement;

import com.webauthn4j.test.TestAttestationStatementUtil;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.*;

class CompoundAttestationStatementTest {

    FIDOU2FAttestationStatement u2f = TestAttestationStatementUtil.createFIDOU2FAttestationStatement();
    PackedAttestationStatement packed = TestAttestationStatementUtil.createBasicPackedAttestationStatement();

    @Test
    void constructor_test1() {
        assertThatCode(() -> new CompoundAttestationStatement(u2f, packed)).doesNotThrowAnyException();
    }

    @Test
    void constructor_test2() {
        assertThatCode(() -> new CompoundAttestationStatement(Arrays.asList(u2f, packed))).doesNotThrowAnyException();
    }

    @Test
    void validate_test1(){
        CompoundAttestationStatement compoundAttestationStatement = new CompoundAttestationStatement(packed, u2f);
        assertThatCode(compoundAttestationStatement::validate).doesNotThrowAnyException();
    }

    @Test
    void validate_test2(){
        CompoundAttestationStatement compoundAttestationStatement = new CompoundAttestationStatement();
        assertThatThrownBy(compoundAttestationStatement::validate).isInstanceOf(ConstraintViolationException.class);
    }

    @Test
    void validate_test3(){
        CompoundAttestationStatement compoundAttestationStatement = new CompoundAttestationStatement(packed);
        assertThatThrownBy(compoundAttestationStatement::validate).isInstanceOf(ConstraintViolationException.class);
    }

    @Test
    void validate_test4(){
        CompoundAttestationStatement compoundAttestationStatement = new CompoundAttestationStatement(u2f, new CompoundAttestationStatement(u2f, packed));
        assertThatThrownBy(compoundAttestationStatement::validate).isInstanceOf(ConstraintViolationException.class);
    }


    @Test
    void getter_test(){
        CompoundAttestationStatement instanceA = new CompoundAttestationStatement(u2f, packed);
        assertThat(instanceA.getFormat()).isEqualTo(CompoundAttestationStatement.FORMAT);
        assertThat(instanceA.getAttStmt()).isEqualTo(Arrays.asList(u2f, packed));
    }

    @Test
    void equals_hashCode_test() {
        CompoundAttestationStatement instanceA = new CompoundAttestationStatement(u2f, packed);
        CompoundAttestationStatement instanceB = new CompoundAttestationStatement(u2f, packed);

        assertAll(
                () -> assertThat(instanceA).isEqualTo(instanceB),
                () -> assertThat(instanceA).hasSameHashCodeAs(instanceB)
        );
    }

}