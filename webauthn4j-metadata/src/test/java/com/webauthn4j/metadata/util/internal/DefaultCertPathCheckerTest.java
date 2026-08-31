package com.webauthn4j.metadata.util.internal;

import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.metadata.CertPathCheckContext;
import com.webauthn4j.metadata.data.MetadataBLOB;
import com.webauthn4j.metadata.data.MetadataBLOBFactory;
import com.webauthn4j.metadata.exception.CertPathCheckException;
import com.webauthn4j.util.CertificateUtil;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
class DefaultCertPathCheckerTest {

    @Test
    void invalid_cert_path_throws_CertPathCheckException_when_revocation_check_is_disabled_test() throws Exception {
        String blobJwt = Files.readString(Paths.get(ClassLoader.getSystemResource("integration/component/blob.jwt").toURI()));
        MetadataBLOB metadataBLOB = new MetadataBLOBFactory(new ObjectConverter()).parse(blobJwt);
        List<? extends Certificate> certificates = metadataBLOB.getHeader().getX5c().getCertificates();
        X509Certificate trustAnchorCertificate = (X509Certificate) certificates.get(certificates.size() - 1);
        CertPathCheckContext context = new CertPathCheckContext(
                CertificateUtil.generateCertPath(certificates.subList(0, certificates.size() - 1)),
                Collections.singleton(new TrustAnchor(trustAnchorCertificate, null)),
                false);

        assertThatThrownBy(() -> new DefaultCertPathChecker().check(context))
                .isInstanceOf(CertPathCheckException.class);
    }
}
