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

package net.sharplab.springframework.security.webauthn.converter;

import net.sharplab.springframework.security.webauthn.attestation.WebAuthnAttestationObject;
import net.sharplab.springframework.security.webauthn.attestation.authenticator.WebAuthnAuthenticatorData;
import net.sharplab.springframework.security.webauthn.attestation.statement.FIDOU2FAttestationStatement;
import net.sharplab.springframework.security.webauthn.attestation.statement.WebAuthnAttestationStatement;
import org.junit.Ignore;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class Base64StringToWebAuthnAttestationObjectConverterTest {

    private Base64StringToWebAuthnAttestationObjectConverter target = new Base64StringToWebAuthnAttestationObjectConverter();

    @Ignore
    @Test
    public void convert_test(){
        String testData = "o2hhdXRoRGF0YVkBLEmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAKIACP59QEXMiaemII_WZWgoIBmmkh7u5xvxoHPRL-RV5NmOWCp9_fTzb8OSLyJC-digpP3ca_tDREm1wSwAo7-Q-WTI_PZ4D7dpj8JxNm3ewHpLpo42QSiRb1joquwVFg13fp9S4-uYiUp-pSozyH_tghNpcOqJ-riHuXu2kLR5Cr2XBa7IQpswofjHL57GQkxvOvifcwaD2gEYWoAMY0N9vn2jY2FsZ2VFUzI1NmF4WCBrz3D7ICYMH0jEkDdGip-1kNA-dzRbNsoxUuAbmiOczmF5WCBpN2_GpRfY3MKJRPE0gTLFdmUJlahghRNeb4rV8sdtrWNmbXRoZmlkby11MmZnYXR0U3RtdKJjeDVjgVkBNzCCATMwgdmgAwIBAgIFAIIN5C0wCgYIKoZIzj0EAwIwITEfMB0GA1UEAxMWRmlyZWZveCBVMkYgU29mdCBUb2tlbjAeFw0xNzA4MDYxMzQ3NTBaFw0xNzA4MDgxMzQ3NTBaMCExHzAdBgNVBAMTFkZpcmVmb3ggVTJGIFNvZnQgVG9rZW4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATt8WX-ju7pwFW1dsU63HaoCJdkZQ1ZrMTmq5egYzkqirtpq7BAAf-2sgWHJA_AhpTy56kfrEx0csiAU-Mvj6oqMAoGCCqGSM49BAMCA0kAMEYCIQCBOXuTIst0TswK3mHn34VOEG_2Py5bWOt3PQtWXH6d9AIhALDVZWNPvukW9eniDcWZ-MMSq4C5V98UrcUW9d49zroEY3NpZ1hHMEUCIQDj2wuWgR6Rz8jvWYjsqZt_Va5FUl4POFuPehYAXeG-oQIgFGIm73KFf_lKqv8KVxpJb_IWqJTF3i97wTo3UjfJImk";
        WebAuthnAttestationObject attestationObject = target.convert(testData);
        WebAuthnAuthenticatorData webAuthnAuthenticatorData = attestationObject.getAuthenticatorData();
        String format = attestationObject.getFormat();
        WebAuthnAttestationStatement attestationStatement = attestationObject.getAttestationStatement();

        assertThat(webAuthnAuthenticatorData).isNotNull();
        assertThat(format).isEqualTo("fido-u2f");
        assertThat(attestationStatement).isInstanceOf(FIDOU2FAttestationStatement.class);
    }

    @Test(expected = IllegalArgumentException.class)
    public void convert_test_with_illegal_input(){
        String testData = "illegal input";
        target.convert(testData);
    }


}
