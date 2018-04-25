package net.sharplab.springframework.security.webauthn.sample.util.modelmapper;

import com.webauthn4j.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.attestation.authenticator.ESCredentialPublicKey;
import com.webauthn4j.attestation.authenticator.RSCredentialPublicKey;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.AbstractCredentialPublicKeyVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.ESCredentialPublicKeyVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.RSCredentialPublicKeyVO;
import org.modelmapper.Converter;
import org.modelmapper.spi.MappingContext;


/**
 * Converter which converts from {@link AbstractCredentialPublicKeyVO} to {@link CredentialPublicKey}
 */
public class CredentialPublicKeyVOToCredentialPublicKeyConverter implements Converter<AbstractCredentialPublicKeyVO, CredentialPublicKey> {
    @Override
    public CredentialPublicKey convert(MappingContext<AbstractCredentialPublicKeyVO, CredentialPublicKey> context) {
        AbstractCredentialPublicKeyVO source = context.getSource();
        CredentialPublicKey destination = context.getDestination();
        if (source == null) {
            return null;
        }
        if (source.getClass() == RSCredentialPublicKeyVO.class) {
            if (destination == null) {
                destination = new RSCredentialPublicKey();
            }
            context.getMappingEngine().map(context.create((RSCredentialPublicKeyVO) source, (RSCredentialPublicKey)destination));
        } else if (source.getClass() == ESCredentialPublicKeyVO.class) {
            if (destination == null) {
                destination = new ESCredentialPublicKey();
            }
            context.getMappingEngine().map(context.create((ESCredentialPublicKeyVO) source, (ESCredentialPublicKey)destination));
        } else {
            throw new IllegalArgumentException();
        }
        return destination;
    }
}
