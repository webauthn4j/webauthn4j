package net.sharplab.springframework.security.webauthn.sample.test;

import net.sharplab.springframework.security.webauthn.sample.domain.model.User;
import org.springframework.util.Base64Utils;

/**
 * A utility class for sample module test
 */
public class SampleTestUtil {

    private SampleTestUtil(){}

    public static User createUser(){
        User user = new User();
        user.setId(1);
        user.setUserHandle(Base64Utils.decodeFromUrlSafeString("TFmvUeeRSQyMUxLDq6x6GA"));
        user.setFirstName("John");
        user.setLastName("Doe");
        user.setEmailAddress("john.doe@example.com");
        user.setPassword("$2a$10$P2/aZvvln5dWs9T96ycx0eNFS1EwdiElzRjMObg8j0rTDISHMEdoq");
        user.setLocked(false);
        return user;
    }
}
