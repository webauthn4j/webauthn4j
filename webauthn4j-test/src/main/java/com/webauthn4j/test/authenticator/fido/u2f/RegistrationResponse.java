package com.webauthn4j.test.authenticator.fido.u2f;

import com.webauthn4j.util.UnsignedNumberUtil;

import java.nio.ByteBuffer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class RegistrationResponse {

    private static final byte RESERVED_BYTE = 0x05;

    private byte reservedByte;
    private byte[] userPublicKey;
    private byte[] keyHandle;
    private X509Certificate attestationCertificate;
    private byte[] signature;

    public RegistrationResponse(byte reservedByte, byte[] userPublicKey, byte[] keyHandle, X509Certificate attestationCertificate, byte[] signature) {
        if(userPublicKey.length != 65){throw new IllegalArgumentException("userPublicKey must be 65 bytes");}
        if(keyHandle.length > UnsignedNumberUtil.BYTE_MAX){throw new IllegalArgumentException("keyHandle length must not exceed " + UnsignedNumberUtil.BYTE_MAX + " bytes");}

        this.reservedByte = reservedByte;
        this.userPublicKey = userPublicKey;
        this.keyHandle = keyHandle;
        this.attestationCertificate = attestationCertificate;
        this.signature = signature;
    }

    public RegistrationResponse(byte[] userPublicKey, byte[] keyHandle, X509Certificate attestationCertificate, byte[] signature) {
        this(RESERVED_BYTE, userPublicKey, keyHandle, attestationCertificate, signature);
    }

    public byte getReservedByte() {
        return reservedByte;
    }

    public byte[] getUserPublicKey() {
        return userPublicKey;
    }

    public byte[] getKeyHandle() {
        return keyHandle;
    }

    public X509Certificate getAttestationCertificate() {
        return attestationCertificate;
    }

    public byte[] getSignature() {
        return signature;
    }

    public byte[] getBytes(){
        try {
            byte keyHandleLength = (byte)keyHandle.length;
            byte[] attestationCertificateBytes = attestationCertificate.getEncoded();
            return ByteBuffer.allocate(1 + 65 + 1 + keyHandle.length + attestationCertificateBytes.length + signature.length)
                    .put(reservedByte).put(userPublicKey).put(keyHandleLength).put(keyHandle).put(attestationCertificateBytes).put(signature).array();
        } catch (CertificateEncodingException e) {
            throw new FIDOU2FException(e);
        }
    }
}
