package net.sharplab.springframework.security.webauthn.sample.infrastructure.util.jpa.converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.sharplab.springframework.security.webauthn.sample.domain.vo.CredentialPublicKeyVO;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;
import java.io.IOException;
import java.io.UncheckedIOException;

@Converter
public class CredentialPublicKeyVOConverter implements AttributeConverter<CredentialPublicKeyVO, String> {

    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String convertToDatabaseColumn(CredentialPublicKeyVO attribute) {
        try {
            return objectMapper.writeValueAsString(attribute);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Override
    public CredentialPublicKeyVO convertToEntityAttribute(String dbData) {
        try {
            return objectMapper.readValue(dbData, CredentialPublicKeyVO.class);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
