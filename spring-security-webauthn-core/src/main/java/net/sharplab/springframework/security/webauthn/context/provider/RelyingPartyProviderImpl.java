/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.sharplab.springframework.security.webauthn.context.provider;

import com.webauthn4j.client.Origin;
import com.webauthn4j.client.challenge.Challenge;
import com.webauthn4j.RelyingParty;
import net.sharplab.springframework.security.webauthn.challenge.ChallengeRepository;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * {@inheritDoc}
 */
public class RelyingPartyProviderImpl implements RelyingPartyProvider {

    private String rpId = null;
    private ChallengeRepository challengeRepository;

    public RelyingPartyProviderImpl(ChallengeRepository challengeRepository) {
        this.challengeRepository = challengeRepository;
    }

    public RelyingParty provide(HttpServletRequest request, HttpServletResponse response) {

        Origin origin = obtainOrigin(request);
        Challenge savedChallenge = obtainSavedChallenge(request);

        String rpId = origin.getServerName();
        if (this.rpId != null) {
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


    private Origin obtainOrigin(HttpServletRequest request) {
        return new Origin(request.getScheme(), request.getServerName(), request.getServerPort());
    }

    private Challenge obtainSavedChallenge(HttpServletRequest request) {
        return challengeRepository.loadChallenge(request);
    }
}
