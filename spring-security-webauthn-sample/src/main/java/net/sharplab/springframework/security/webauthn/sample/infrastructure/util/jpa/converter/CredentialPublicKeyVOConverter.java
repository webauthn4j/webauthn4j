package net.sharplab.springframework.security.webauthn.sample.infrastructure.util.jpa.converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.AbstractCredentialPublicKeyVO;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;
import java.io.IOException;
import java.io.UncheckedIOException;

@Converter
public class CredentialPublicKeyVOConverter implements AttributeConverter<AbstractCredentialPublicKeyVO, String> {

    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String convertToDatabaseColumn(AbstractCredentialPublicKeyVO attribute) {
        try {
            return objectMapper.writeValueAsString(attribute);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public AbstractCredentialPublicKeyVO convertToEntityAttribute(String dbData) {
        try {
            return objectMapper.readValue(dbData, AbstractCredentialPublicKeyVO.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
