package net.sharplab.springframework.security.webauthn.sample.domain.util.modelmapper.converter;

import net.sharplab.springframework.security.webauthn.attestation.authenticator.AbstractCredentialPublicKey;
import net.sharplab.springframework.security.webauthn.attestation.authenticator.ESCredentialPublicKey;
import net.sharplab.springframework.security.webauthn.attestation.authenticator.RSCredentialPublicKey;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.CredentialPublicKeyVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.ESCredentialPublicKeyVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.RSCredentialPublicKeyVO;
import org.modelmapper.Converter;
import org.modelmapper.spi.MappingContext;


/**
 * Converter which converts from {@link AbstractCredentialPublicKey} to {@link CredentialPublicKeyVO}
 */
public class CredentialPublicKeyToCredentialPublicKeyVOConverter implements Converter<AbstractCredentialPublicKey, CredentialPublicKeyVO> {
    @Override
    public CredentialPublicKeyVO convert(MappingContext<AbstractCredentialPublicKey, CredentialPublicKeyVO> context) {
        AbstractCredentialPublicKey source = context.getSource();
        CredentialPublicKeyVO destination = context.getDestination();

        if (source == null) {
            return null;
        }
        if (source.getClass() == RSCredentialPublicKey.class) {
            if (destination == null) {
                destination = new RSCredentialPublicKeyVO();
            }
            context.getMappingEngine().map(context.create((RSCredentialPublicKey) source, destination));
        } else if (source.getClass() == ESCredentialPublicKey.class) {
            if (destination == null) {
                destination = new ESCredentialPublicKeyVO();
            }
            context.getMappingEngine().map(context.create((ESCredentialPublicKey) source, destination));
        } else {
            throw new IllegalArgumentException();
        }
        return destination;
    }
}
