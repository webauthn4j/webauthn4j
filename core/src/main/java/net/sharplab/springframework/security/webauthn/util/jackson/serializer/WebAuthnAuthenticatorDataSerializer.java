package net.sharplab.springframework.security.webauthn.util.jackson.serializer;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import net.sharplab.springframework.security.webauthn.attestation.authenticator.AbstractCredentialPublicKey;
import net.sharplab.springframework.security.webauthn.attestation.authenticator.WebAuthnAttestedCredentialData;
import net.sharplab.springframework.security.webauthn.attestation.authenticator.WebAuthnAuthenticatorData;
import net.sharplab.springframework.security.webauthn.attestation.authenticator.extension.Extension;
import net.sharplab.springframework.security.webauthn.util.UnsignedNumberUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;

/**
 * Jackson Serializer for WebAuthnAuthenticatorData
 */
public class WebAuthnAuthenticatorDataSerializer extends StdSerializer<WebAuthnAuthenticatorData> {

    private ObjectMapper objectMapper = new ObjectMapper(new CBORFactory());

    public WebAuthnAuthenticatorDataSerializer() {
        super(WebAuthnAuthenticatorData.class);
    }

    @Override
    public void serialize(WebAuthnAuthenticatorData value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        gen.writeBinary(serialize(value));
    }

    byte[] serialize(WebAuthnAuthenticatorData value) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(value.getRpIdHash());
        byteArrayOutputStream.write(new byte[]{value.getFlags()});
        byteArrayOutputStream.write(UnsignedNumberUtil.toBytes(value.getCounter()));
        if(value.getAttestationData() != null){
            byteArrayOutputStream.write(serializeAttestationData(value.getAttestationData()));
        }
        byteArrayOutputStream.write(serializeExtensions(value.getExtensions()));
        return byteArrayOutputStream.toByteArray();
    }

    private byte[] serializeAttestationData(WebAuthnAttestedCredentialData attestationData) throws IOException {

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(attestationData.getAaGuid());
        byteArrayOutputStream.write(UnsignedNumberUtil.toBytes(attestationData.getCredentialId().length));
        byteArrayOutputStream.write(attestationData.getCredentialId());
        byteArrayOutputStream.write(serializeCredentialPublicKey(attestationData.getCredentialPublicKey()));
        return byteArrayOutputStream.toByteArray();
    }

    private byte[] serializeExtensions(List<Extension> extensions){
        return new byte[0]; //TODO: to be implemented
    }

    private byte[] serializeCredentialPublicKey(AbstractCredentialPublicKey credentialPublicKey) throws JsonProcessingException {
        return objectMapper.writeValueAsBytes(credentialPublicKey);
    }

}
