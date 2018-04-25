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
 * Converter which converts from {@link CredentialPublicKey} to {@link AbstractCredentialPublicKeyVO}
 */
public class CredentialPublicKeyToCredentialPublicKeyVOConverter implements Converter<CredentialPublicKey, AbstractCredentialPublicKeyVO> {
    @Override
    public AbstractCredentialPublicKeyVO convert(MappingContext<CredentialPublicKey, AbstractCredentialPublicKeyVO> context) {
        CredentialPublicKey source = context.getSource();
        AbstractCredentialPublicKeyVO destination = context.getDestination();

        if (source == null) {
            return null;
        }
        if (source.getClass() == RSCredentialPublicKey.class) {
            if (destination == null) {
                destination = new RSCredentialPublicKeyVO();
            }
            context.getMappingEngine().map(context.create((RSCredentialPublicKey) source, (RSCredentialPublicKeyVO)destination));
        } else if (source.getClass() == ESCredentialPublicKey.class) {
            if (destination == null) {
                destination = new ESCredentialPublicKeyVO();
            }
            context.getMappingEngine().map(context.create((ESCredentialPublicKey) source, (ESCredentialPublicKeyVO)destination));
        } else {
            throw new IllegalArgumentException();
        }
        return destination;
    }
}
