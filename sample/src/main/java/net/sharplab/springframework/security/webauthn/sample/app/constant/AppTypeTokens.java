package net.sharplab.springframework.security.webauthn.sample.app.constant;

import net.sharplab.springframework.security.webauthn.sample.app.api.admin.CandidateGroupDto;
import net.sharplab.springframework.security.webauthn.sample.app.api.admin.CandidateUserDto;
import net.sharplab.springframework.security.webauthn.sample.app.web.AuthenticatorForm;
import net.sharplab.springframework.security.webauthn.sample.domain.model.Authenticator;
import org.modelmapper.TypeToken;
import org.springframework.data.domain.PageImpl;

import java.lang.reflect.Type;
import java.util.List;

/**
 * Application Layer TypeTokens
 */
public class AppTypeTokens {

    public static final Type CandidateUserDtoPage = new TypeToken<PageImpl<CandidateUserDto>>(){}.getType();
    public static final Type CandidateGroupDtoPage = new TypeToken<PageImpl<CandidateGroupDto>>(){}.getType();

    public static final Type AuthenticatorFormList = new TypeToken<List<AuthenticatorForm>>(){}.getType();

    private AppTypeTokens(){}
}
