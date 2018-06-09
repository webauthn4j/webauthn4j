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

package com.webauthn4j.test.authenticator.fido.u2f;

import com.webauthn4j.util.UnsignedNumberUtil;
import com.webauthn4j.util.WIP;

import java.nio.ByteBuffer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

@WIP
public class RegistrationResponse {

    private static final byte RESERVED_BYTE = 0x05;

    private byte reservedByte;
    private byte[] userPublicKey;
    private byte[] keyHandle;
    private X509Certificate attestationCertificate;
    private byte[] signature;

    public RegistrationResponse(byte reservedByte, byte[] userPublicKey, byte[] keyHandle, X509Certificate attestationCertificate, byte[] signature) {
        if (userPublicKey.length != 65) {
            throw new IllegalArgumentException("userPublicKey must be 65 bytes");
        }
        if (keyHandle.length > (UnsignedNumberUtil.UNSIGNED_BYTE_MAX)) {
            throw new IllegalArgumentException("keyHandle length must not exceed " + (UnsignedNumberUtil.UNSIGNED_BYTE_MAX) + " bytes");
        }

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

    public byte[] getBytes() {
        try {
            byte keyHandleLength = (byte) keyHandle.length;
            byte[] attestationCertificateBytes = attestationCertificate.getEncoded();
            return ByteBuffer.allocate(1 + 65 + 1 + keyHandle.length + attestationCertificateBytes.length + signature.length)
                    .put(reservedByte).put(userPublicKey).put(keyHandleLength).put(keyHandle).put(attestationCertificateBytes).put(signature).array();
        } catch (CertificateEncodingException e) {
            throw new FIDOU2FException(e);
        }
    }
}
