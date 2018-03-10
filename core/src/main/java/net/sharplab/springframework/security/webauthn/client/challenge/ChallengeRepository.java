package net.sharplab.springframework.security.webauthn.client.challenge;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 * An API to allow changing the method in which the expected {@link Challenge} is
 * associated to the {@link HttpServletRequest}. For example, it may be stored in
 * {@link HttpSession}.
 *
 * @author Rob Winch
 * @see HttpSessionChallengeRepository
 * @since 3.2
 */
public interface ChallengeRepository {

    /**
     * Generates a {@link Challenge}
     *
     * @return the {@link Challenge} that was generated. Cannot be null.
     */
    Challenge generateChallenge();

    /**
     * Saves the {@link Challenge} using the {@link HttpServletRequest} and
     * {@link HttpServletResponse}. If the {@link Challenge} is null, it is the same as
     * deleting it.
     *
     * @param challenge the {@link Challenge} to save or null to delete
     * @param request   the {@link HttpServletRequest} to use
     * @param response  the {@link HttpServletResponse} to use
     */
    void saveChallenge(Challenge challenge, HttpServletRequest request,
                       HttpServletResponse response);

    /**
     * Loads the expected {@link Challenge} from the {@link HttpServletRequest}
     *
     * @param request the {@link HttpServletRequest} to use
     * @return the {@link Challenge} or null if none exists
     */
    Challenge loadChallenge(HttpServletRequest request);
}

