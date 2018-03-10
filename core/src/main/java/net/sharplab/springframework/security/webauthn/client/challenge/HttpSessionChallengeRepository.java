package net.sharplab.springframework.security.webauthn.client.challenge;

import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.nio.ByteBuffer;
import java.util.UUID;

/**
 * ChallengeRequestDataValueProcessor
 * <p>
 * Class design is based on {@link HttpSessionCsrfTokenRepository}
 */
public class HttpSessionChallengeRepository implements ChallengeRepository {

    private static final String DEFAULT_CHALLENGE_ATTR_NAME = HttpSessionChallengeRepository.class
            .getName().concat(".CHALLENGE");

    private String sessionAttributeName = DEFAULT_CHALLENGE_ATTR_NAME;

    @Override
    public Challenge generateChallenge() {
        return new DefaultChallenge(createNewChallenge());
    }

    @Override
    public void saveChallenge(Challenge challenge, HttpServletRequest request, HttpServletResponse response) {
        if (challenge == null) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.removeAttribute(this.sessionAttributeName);
            }
        } else {
            HttpSession session = request.getSession();
            session.setAttribute(this.sessionAttributeName, challenge);
        }
    }

    @Override
    public Challenge loadChallenge(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        return (Challenge) session.getAttribute(this.sessionAttributeName);
    }

    /**
     * Sets the {@link HttpSession} attribute name that the {@link Challenge} is stored in
     *
     * @param sessionAttributeName the new attribute name to use
     */
    public void setSessionAttributeName(String sessionAttributeName) {
        Assert.hasLength(sessionAttributeName,
                "sessionAttributename cannot be null or empty");
        this.sessionAttributeName = sessionAttributeName;
    }

    private byte[] createNewChallenge() {
        UUID uuid = UUID.randomUUID();
        long hi = uuid.getMostSignificantBits();
        long lo = uuid.getLeastSignificantBits();
        return ByteBuffer.allocate(16).putLong(hi).putLong(lo).array();
    }
}
