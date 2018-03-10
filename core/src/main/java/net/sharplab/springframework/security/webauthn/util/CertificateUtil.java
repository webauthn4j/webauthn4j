package net.sharplab.springframework.security.webauthn.util;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.List;
import java.util.Set;

/**
 * A Utility class for metadata.certs
 */
public class CertificateUtil {

    private static CertificateFactory certificateFactory;

    private CertificateUtil(){}

    static{
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new IllegalStateException(e);
        }
    }

    public static CertPathValidator generateCertPathValidator(){
        try {
            return CertPathValidator.getInstance("PKIX");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e); //TODO
        }
    }

    public static PKIXParameters generatePKIXParameters(Set<TrustAnchor> trustAnchors){
        try {
            return new PKIXParameters(trustAnchors);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalArgumentException(e); //TODO
        }
    }

    public static KeyStore generateKeyStore(){
        try {
            return KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    public static CertPath generateCertPath(List<Certificate> certificates){
        try {
            return certificateFactory.generateCertPath(certificates);
        } catch (CertificateException e) {
            throw new IllegalArgumentException(e); //TODO
        }
    }

    public static X509Certificate generateX509Certificate(byte[] bytes){
        return generateX509Certificate(new ByteArrayInputStream(bytes));
    }

    public static X509Certificate generateX509Certificate(InputStream inputStream){
        try {
            return (X509Certificate) certificateFactory.generateCertificate(inputStream);
        } catch (CertificateException e) {
            throw new IllegalArgumentException(e); //TODO
        }
    }

    public static boolean isSelfSigned(X509Certificate certificate){
        Signature signature = SignatureUtil.createSignature(certificate.getSigAlgName());
        try {
            signature.initVerify(certificate.getPublicKey());
        } catch (InvalidKeyException e) {
            return false;
        }
        try {
            signature.update(certificate.getPublicKey().getEncoded());
            signature.verify(certificate.getSignature());
        } catch (SignatureException e) {
            return false;
        }
        return true;
    }

}
