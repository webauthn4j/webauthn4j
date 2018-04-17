package net.sharplab.springframework.security.webauthn.sample.util.modelmapper;

import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.client.challenge.DefaultChallenge;
import org.modelmapper.AbstractConverter;
import org.springframework.util.Base64Utils;

/**
 * Converter which converts from {@link String} to {@link Challenge}
 */
public class StringToChallengeConverter extends AbstractConverter<String, Challenge> {

    @Override
    protected Challenge convert(String source) {
        byte[] challenge = Base64Utils.decodeFromUrlSafeString(source);
        return new DefaultChallenge(challenge);
    }
}
