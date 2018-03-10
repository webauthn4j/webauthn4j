package net.sharplab.springframework.security.webauthn.sample.infrastructure.util.jpa.converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.AttestationStatementVO;

import javax.persistence.AttributeConverter;
import java.io.IOException;
import java.io.UncheckedIOException;

/**
 * AttestationStatementVOConverter
 */
public class AttestationStatementVOConverter implements AttributeConverter<AttestationStatementVO, String> {

    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String convertToDatabaseColumn(AttestationStatementVO attribute) {
        try {
            return objectMapper.writeValueAsString(attribute);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public AttestationStatementVO convertToEntityAttribute(String dbData) {
        try {
            return objectMapper.readValue(dbData, AttestationStatementVO.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
