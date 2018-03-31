package net.sharplab.springframework.security.webauthn.sample.domain.util.modelmapper.converter;

import com.webauthn4j.webauthn.attestation.authenticator.AbstractCredentialPublicKey;
import com.webauthn4j.webauthn.attestation.authenticator.CredentialPublicKey;
import com.webauthn4j.webauthn.attestation.authenticator.ESCredentialPublicKey;
import com.webauthn4j.webauthn.attestation.authenticator.RSCredentialPublicKey;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.CredentialPublicKeyVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.ESCredentialPublicKeyVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.RSCredentialPublicKeyVO;
import org.modelmapper.Converter;
import org.modelmapper.spi.MappingContext;


/**
 * Converter which converts from {@link CredentialPublicKeyVO} to {@link CredentialPublicKey}
 */
public class CredentialPublicKeyVOToCredentialPublicKeyConverter implements Converter<CredentialPublicKeyVO, CredentialPublicKey> {
    @Override
    public CredentialPublicKey convert(MappingContext<CredentialPublicKeyVO, CredentialPublicKey> context) {
        CredentialPublicKeyVO source = context.getSource();
        CredentialPublicKey destination = context.getDestination();
        if (source == null) {
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
