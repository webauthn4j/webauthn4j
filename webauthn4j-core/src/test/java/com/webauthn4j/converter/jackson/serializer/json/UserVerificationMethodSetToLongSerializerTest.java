package com.webauthn4j.converter.jackson.serializer.json;

import com.webauthn4j.data.UserVerificationMethod;
import org.junit.jupiter.api.Test;
import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;

import java.util.EnumSet;
import java.util.Set;

import static org.mockito.Mockito.*;

class UserVerificationMethodSetToLongSerializerTest {

    private final UserVerificationMethodSetToLongSerializer serializer = new UserVerificationMethodSetToLongSerializer();

    @Test
    void single_value_test() throws Exception {
        JsonGenerator gen = mock(JsonGenerator.class);
        Set<UserVerificationMethod> set = EnumSet.of(UserVerificationMethod.FINGERPRINT_INTERNAL);
        serializer.serialize(set, gen, mock(SerializationContext.class));
        verify(gen).writeNumber(2L);
    }

    @Test
    void multiple_values_test() throws Exception {
        JsonGenerator gen = mock(JsonGenerator.class);
        Set<UserVerificationMethod> set = EnumSet.of(
                UserVerificationMethod.PRESENCE_INTERNAL,
                UserVerificationMethod.FINGERPRINT_INTERNAL
        );
        serializer.serialize(set, gen, mock(SerializationContext.class));
        verify(gen).writeNumber(3L);
    }

    @Test
    void empty_set_test() throws Exception {
        JsonGenerator gen = mock(JsonGenerator.class);
        Set<UserVerificationMethod> set = EnumSet.noneOf(UserVerificationMethod.class);
        serializer.serialize(set, gen, mock(SerializationContext.class));
        verify(gen).writeNumber(0L);
    }
}
