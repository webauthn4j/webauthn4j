package net.sharplab.springframework.security.webauthn.utils.jackson.deserializer;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.sharplab.springframework.security.webauthn.client.ClientData;
import net.sharplab.springframework.security.webauthn.test.CoreTestUtil;
import org.junit.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test for ChallengeDeserializer
 */
public class ChallengeDeserializerTest {

    @Test
    public void test() throws IOException {
        ObjectMapper objectMapper = CoreTestUtil.createJsonMapper();

        //Given
        String input = "{ \"challenge\" : \"\" }";

        //When
        ClientData result = objectMapper.readValue(input, ClientData.class);

        //Then
        assertThat(result).extracting("challenge").isNotNull();
        assertThat(result.getChallenge().getValue()).hasSize(0);
    }
}
