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
 * Converter which converts from {@link CredentialPublicKeyVO} to {@link AbstractCredentialPublicKey}
 */
public class CredentialPublicKeyVOToCredentialPublicKeyConverter implements Converter<CredentialPublicKeyVO, AbstractCredentialPublicKey> {
    @Override
    public AbstractCredentialPublicKey convert(MappingContext<CredentialPublicKeyVO, AbstractCredentialPublicKey> context) {
        CredentialPublicKeyVO source = context.getSource();
        AbstractCredentialPublicKey destination = context.getDestination();
        if(source == null){
            return null;
        }
        if (source.getClass() == RSCredentialPublicKeyVO.class) {
            if (destination == null) {
                destination = new RSCredentialPublicKey();
            }
            context.getMappingEngine().map(context.create((RSCredentialPublicKeyVO) source, destination));
        } else if (source.getClass() == ESCredentialPublicKeyVO.class) {
            if (destination == null) {
                destination = new ESCredentialPublicKey();
            }
            context.getMappingEngine().map(context.create((ESCredentialPublicKeyVO) source, destination));
        } else {
            throw new IllegalArgumentException();
        }
        return destination;
    }
}
