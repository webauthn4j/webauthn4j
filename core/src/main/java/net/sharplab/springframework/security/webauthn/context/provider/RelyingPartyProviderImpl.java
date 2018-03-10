package net.sharplab.springframework.security.webauthn.context.provider;

import net.sharplab.springframework.security.webauthn.client.Origin;
import net.sharplab.springframework.security.webauthn.client.challenge.Challenge;
import net.sharplab.springframework.security.webauthn.client.challenge.ChallengeRepository;
import net.sharplab.springframework.security.webauthn.context.RelyingParty;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * {@inheritDoc}
 */
public class RelyingPartyProviderImpl implements RelyingPartyProvider {

    private String rpId = null;
    private ChallengeRepository challengeRepository;

    public RelyingPartyProviderImpl(ChallengeRepository challengeRepository){
        this.challengeRepository = challengeRepository;
    }

    public RelyingParty provide(HttpServletRequest request, HttpServletResponse response){

        Origin origin = obtainOrigin(request);
        Challenge savedChallenge = obtainSavedChallenge(request);

        String rpId = origin.getServerName();
        if(this.rpId != null){
            rpId = this.rpId;
        }

        return new RelyingParty(origin, rpId, savedChallenge);
    }

    public String getRpId() {
        return rpId;
    }

    public void setRpId(String rpId) {
        this.rpId = rpId;
    }


    private Origin obtainOrigin(HttpServletRequest request){
        return new Origin(request.getScheme(), request.getServerName(), request.getServerPort());
    }

    private Challenge obtainSavedChallenge(HttpServletRequest request) {
        return challengeRepository.loadChallenge(request);
    }
}
