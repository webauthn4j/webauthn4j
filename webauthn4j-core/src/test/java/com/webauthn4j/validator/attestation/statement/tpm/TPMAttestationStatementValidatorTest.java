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

package com.webauthn4j.validator.attestation.statement.tpm;


import com.webauthn4j.data.attestation.statement.TPMEccCurve;
import com.webauthn4j.data.attestation.statement.TPMIAlgHash;
import com.webauthn4j.test.TestDataUtil;
import com.webauthn4j.util.ECUtil;
import com.webauthn4j.util.exception.NotImplementedException;
import com.webauthn4j.validator.RegistrationObject;
import com.webauthn4j.validator.exception.BadAttestationStatementException;
import org.apache.kerby.asn1.type.Asn1Utf8String;
import org.junit.jupiter.api.Test;

import javax.naming.InvalidNameException;
import javax.naming.NamingException;
import javax.naming.ldap.LdapName;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class TPMAttestationStatementValidatorTest {

    private TPMAttestationStatementValidator target = new TPMAttestationStatementValidator();

    @Test
    void validate_test() {
        RegistrationObject registrationObject = TestDataUtil.createRegistrationObjectWithTPMAttestation();
        target.validate(registrationObject);
    }

    @Test
    void validate_non_TPMAttestation_test() {
        RegistrationObject registrationObject = TestDataUtil.createRegistrationObjectWithAndroidKeyAttestation();
        assertThrows(IllegalArgumentException.class,
                () -> target.validate(registrationObject)
        );
    }

    @Test
    void getCurveFromTPMEccCurve_test() {
        assertAll(
                () -> assertThat(target.getCurveFromTPMEccCurve(TPMEccCurve.TPM_ECC_NIST_P256)).isEqualTo(ECUtil.P_256_SPEC.getCurve()),
                () -> assertThat(target.getCurveFromTPMEccCurve(TPMEccCurve.TPM_ECC_NIST_P384)).isEqualTo(ECUtil.P_384_SPEC.getCurve()),
                () -> assertThat(target.getCurveFromTPMEccCurve(TPMEccCurve.TPM_ECC_NIST_P521)).isEqualTo(ECUtil.P_521_SPEC.getCurve()),
                () -> assertThrows(NotImplementedException.class,
                        () -> target.getCurveFromTPMEccCurve(TPMEccCurve.TPM_ECC_NIST_P192)
                )
        );
    }

    @Test
    void getAlgJcaName_test() {
        assertAll(
                () -> assertThat(target.getAlgJcaName(TPMIAlgHash.TPM_ALG_SHA1)).isEqualTo("SHA-1"),
                () -> assertThat(target.getAlgJcaName(TPMIAlgHash.TPM_ALG_SHA256)).isEqualTo("SHA-256"),
                () -> assertThat(target.getAlgJcaName(TPMIAlgHash.TPM_ALG_SHA384)).isEqualTo("SHA-384"),
                () -> assertThat(target.getAlgJcaName(TPMIAlgHash.TPM_ALG_SHA512)).isEqualTo("SHA-512"),
                () -> assertThrows(BadAttestationStatementException.class,
                        () -> target.getAlgJcaName(TPMIAlgHash.TPM_ALG_ERROR)
                ),
                () -> assertThrows(BadAttestationStatementException.class,
                        () -> target.getAlgJcaName(TPMIAlgHash.TPM_ALG_NULL)
                )
        );
    }

    @Test
    void case01_validateSubjectAlternativeName_test() {
            try {
                LdapName directoryName = new LdapName("2.23.133.2.3=#0c0b69643a3030303230303030,2.23.133.2.2=#0c03535054,2.23.133.2.1=#0c0b69643a3439344535343433");
                directoryName.getRdns(); // does not do anything
                byte[] manufacturerAttr = (byte[]) directoryName.getRdns().get(0).toAttributes().get("2.23.133.2.1").get();
                byte[] partNumberAttr = null;
                try {
                    // the next one will cause a NullPointerException, because the index does not move to the next element of the Rdn list
                    partNumberAttr = (byte[]) directoryName.getRdns().get(0).toAttributes().get("2.23.133.2.2").get();
                } catch(NullPointerException e) {
                    e.printStackTrace();

                    fail("Failed, because the index is not increased: " + e.getMessage());
                }
                byte[] firmwareVersionAttr = (byte[]) directoryName.getRdns().get(0).toAttributes().get("2.23.133.2.3").get();

                if (manufacturerAttr != null && partNumberAttr != null && firmwareVersionAttr != null) {
                    fail("Should fail");
                }
            } catch(NamingException e) {
                e.printStackTrace();

                fail(e.getMessage());
            }
    }

    @Test
    void case02_bad_solution_validateSubjectAlternativeName_test() {
        try {
            LdapName directoryName = new LdapName("2.23.133.2.3=#0c0b69643a3030303230303030,2.23.133.2.2=#0c03535054,2.23.133.2.1=#0c0b69643a3439344535343433");
            //being useless: directoryName.getRdns();
            byte[] manufacturerAttr = (byte[]) directoryName.getRdns().get(0).toAttributes().get("2.23.133.2.1").get();
            byte[] partNumberAttr =  (byte[]) directoryName.getRdns().get(1).toAttributes().get("2.23.133.2.2").get();
            byte[] firmwareVersionAttr = (byte[]) directoryName.getRdns().get(2).toAttributes().get("2.23.133.2.3").get();

            assertAll(
                    () -> assertThat(manufacturerAttr).isNotEmpty(),
                    () -> assertThat(partNumberAttr).isNotEmpty(),
                    () -> assertThat(firmwareVersionAttr).isNotEmpty()

            );
        } catch(NamingException e) {
            e.printStackTrace();

            fail(e.getMessage());
        }
    }
}
