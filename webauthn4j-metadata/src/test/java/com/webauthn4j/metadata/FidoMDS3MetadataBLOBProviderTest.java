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

package com.webauthn4j.metadata;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.data.MetadataBLOB;
import com.webauthn4j.metadata.exception.MDSException;
import com.webauthn4j.util.Base64Util;
import com.webauthn4j.util.CertificateUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FidoMDS3MetadataBLOBProviderTest {
    private final X509Certificate rootCertificate = CertificateUtil.generateX509Certificate(Base64Util.decode(
            "MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G" +
                    "A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp" +
                    "Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4" +
                    "MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG" +
                    "A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI" +
                    "hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8" +
                    "RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT" +
                    "gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm" +
                    "KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd" +
                    "QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ" +
                    "XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw" +
                    "DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o" +
                    "LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU" +
                    "RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp" +
                    "jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK" +
                    "6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX" +
                    "mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs" +
                    "Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH" +
                    "WD9f"));

    @Test
    void test(){
        FidoMDS3MetadataBLOBProvider target = new FidoMDS3MetadataBLOBProvider(new ObjectConverter(), rootCertificate);
        MetadataBLOB metadataBLOB = target.provide();
        assertThat(metadataBLOB).isNotNull();
    }

    @Nested
    class when_expired_blob_jwt{

        private FidoMDS3MetadataBLOBProvider target;

        @BeforeEach
        void setup() throws IOException, URISyntaxException {
            HttpClient httpClient = mock(HttpClient.class);
            Path blobJwtPath = Paths.get(ClassLoader.getSystemResource("integration/component/blob.jwt").toURI()); //expired blob
            String blobJwtString = Files.readString(blobJwtPath);
            when(httpClient.fetch(FidoMDS3MetadataBLOBProvider.DEFAULT_BLOB_ENDPOINT)).thenReturn(blobJwtString);
            target = new FidoMDS3MetadataBLOBProvider(new ObjectConverter(), FidoMDS3MetadataBLOBProvider.DEFAULT_BLOB_ENDPOINT, httpClient, Collections.singleton(new TrustAnchor(rootCertificate, null)));
        }

        @Test
        void provide_throws_MDSException() {
            assertThatThrownBy(target::provide).isInstanceOf(MDSException.class);
        }

        @Test
        void provide_does_not_throw_MDSException_when_nop_CertPathChecker_is_configured_through_setCertPathChecker() {
            CertPathChecker certPathChecker = context -> {
                //nop
            };
            target.setCertPathChecker(certPathChecker);
            assertThatCode(target::provide).doesNotThrowAnyException();
            assertThat(target.getCertPathChecker()).isEqualTo(certPathChecker);
        }
    }
}
