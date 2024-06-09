//package com.webauthn4j.async.metadata;
//
//import com.webauthn4j.async.util.internal.FileAsyncUtil;
//import com.webauthn4j.converter.util.ObjectConverter;
//import com.webauthn4j.util.CertificateUtil;
//import org.junit.jupiter.api.Test;
//
//import java.io.File;
//import java.nio.file.Path;
//import java.security.cert.X509Certificate;
//import java.util.concurrent.ExecutionException;
//
//import static org.assertj.core.api.Assertions.assertThat;
//import static org.assertj.core.api.Assertions.assertThatCode;
//
//class FidoMDS3MetadataBLOBAsyncProviderTest {
//
//    @Test
//    void test() throws ExecutionException, InterruptedException {
//        Path rootCertificatePath = new File("src/test/resources/integration/component/root-r3.crt").toPath();
//        byte[] bytes = FileAsyncUtil.load(rootCertificatePath).toCompletableFuture().get();
//        X509Certificate rootCertificate = CertificateUtil.generateX509Certificate(bytes);
//
//        FidoMDS3MetadataBLOBAsyncProvider target = new FidoMDS3MetadataBLOBAsyncProvider(new ObjectConverter(), rootCertificate);
//        var metadataBlob = target.provide().toCompletableFuture().get();
//        assertThatCode(metadataBlob::getPayload).doesNotThrowAnyException();
//        assertThat(metadataBlob.getPayload().getEntries()).isNotEmpty();
//    }
//}