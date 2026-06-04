package com.webauthn4j.converter.jackson.deserializer.json;

import com.webauthn4j.data.UserVerificationMethod;
import org.junit.jupiter.api.Test;
import tools.jackson.core.JsonParser;
import tools.jackson.databind.DeserializationContext;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UserVerificationMethodSetFromLongDeserializerTest {

    private final UserVerificationMethodSetFromLongDeserializer deserializer = new UserVerificationMethodSetFromLongDeserializer();

    @Test
    void single_value_test() {
        Set<UserVerificationMethod> result = deserialize(2L);
        assertThat(result).containsExactly(UserVerificationMethod.FINGERPRINT_INTERNAL);
    }

    @Test
    void multiple_values_bitmask_test() {
        Set<UserVerificationMethod> result = deserialize(3L);
        assertThat(result).containsExactlyInAnyOrder(
                UserVerificationMethod.PRESENCE_INTERNAL,
                UserVerificationMethod.FINGERPRINT_INTERNAL
        );
    }

    @Test
    void zero_test() {
        Set<UserVerificationMethod> result = deserialize(0L);
        assertThat(result).isEmpty();
    }

    @Test
    void all_values_test() {
        long allBits = 0;
        for (UserVerificationMethod m : UserVerificationMethod.values()) {
            allBits |= m.getValue();
        }
        Set<UserVerificationMethod> result = deserialize(allBits);
        assertThat(result).containsExactlyInAnyOrder(UserVerificationMethod.values());
    }

    private Set<UserVerificationMethod> deserialize(long bitmask) {
        JsonParser parser = mock(JsonParser.class);
        when(parser.getLongValue()).thenReturn(bitmask);
        return deserializer.deserialize(parser, mock(DeserializationContext.class));
    }
}
