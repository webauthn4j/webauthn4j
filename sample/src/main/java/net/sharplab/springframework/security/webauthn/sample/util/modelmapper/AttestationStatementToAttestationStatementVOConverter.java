package net.sharplab.springframework.security.webauthn.sample.util.modelmapper;

import com.webauthn4j.attestation.statement.AttestationStatement;
import com.webauthn4j.attestation.statement.FIDOU2FAttestationStatement;
import com.webauthn4j.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.attestation.statement.PackedAttestationStatement;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.AttestationStatementVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.FIDOU2FAttestationStatementVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.NoneAttestationStatementVO;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.PackedAttestationStatementVO;
import org.modelmapper.Converter;
import org.modelmapper.spi.MappingContext;

/**
 * Converter which converts from {@link AttestationStatement} to {@link AttestationStatementVO}
 */
public class AttestationStatementToAttestationStatementVOConverter implements Converter<AttestationStatement, AttestationStatementVO> {

    @Override
    public AttestationStatementVO convert(MappingContext<AttestationStatement, AttestationStatementVO> context) {
        AttestationStatement source = context.getSource();
        AttestationStatementVO destination = context.getDestination();
        if (source == null) {
            return null;
        }
        Class sourceClass = source.getClass();
        if (sourceClass == PackedAttestationStatement.class) {
            if (destination == null) {
                destination = new PackedAttestationStatementVO();
            }
            context.getMappingEngine().map(context.create((PackedAttestationStatement) source, destination));
        } else if (sourceClass == FIDOU2FAttestationStatement.class) {
            if (destination == null) {
                destination = new FIDOU2FAttestationStatementVO();
            }
            context.getMappingEngine().map(context.create((FIDOU2FAttestationStatement) source, destination));
        } else if (sourceClass == NoneAttestationStatement.class) {
            if (destination == null) {
                destination = new NoneAttestationStatementVO();
            }
            context.getMappingEngine().map(context.create((NoneAttestationStatement) source, destination));
        } else {
            throw new IllegalArgumentException();
        }
        return destination;
    }
}
