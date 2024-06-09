package test;

import com.webauthn4j.converter.AuthenticationExtensionsClientOutputsConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticatorAttestationResponse;
import com.webauthn4j.data.PublicKeyCredential;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.test.EmulatorUtil;
import com.webauthn4j.test.authenticator.u2f.FIDOU2FAuthenticatorAdaptor;
import com.webauthn4j.test.authenticator.webauthn.WebAuthnAuthenticatorAdaptor;
import com.webauthn4j.test.client.ClientPlatform;

import java.util.Collections;

public class WebAuthnTestUtil {

    private static final ObjectConverter objectConverter = new ObjectConverter();
    private static final AuthenticationExtensionsClientOutputsConverter authenticationExtensionsClientOutputsConverter = new AuthenticationExtensionsClientOutputsConverter(objectConverter);

    private WebAuthnTestUtil(){}


    public static RegistrationRequest toRegistrationRequest(PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> publicKeyCredential){
        var authenticatorAttestationResponse = publicKeyCredential.getResponse();
        var clientExtensionResults = publicKeyCredential.getClientExtensionResults();
        var clientExtensionJSON = authenticationExtensionsClientOutputsConverter.convertToString(clientExtensionResults);
        return new RegistrationRequest(
                authenticatorAttestationResponse.getAttestationObject(),
                authenticatorAttestationResponse.getClientDataJSON(),
                clientExtensionJSON,
                Collections.emptySet()
        );
    }

    public static ClientPlatform createClientPlatformWithAndroidKeyAuthenticator(Origin origin) {
        var webAuthnAuthenticatorAdaptor = new WebAuthnAuthenticatorAdaptor(EmulatorUtil.ANDROID_KEY_AUTHENTICATOR);
        return new ClientPlatform(origin, webAuthnAuthenticatorAdaptor);
    }

    public static ClientPlatform createClientPlatformWithAndroidSafetyNetAuthenticator(Origin origin) {
        var webAuthnAuthenticatorAdaptor = new WebAuthnAuthenticatorAdaptor(EmulatorUtil.ANDROID_SAFETY_NET_AUTHENTICATOR);
        return new ClientPlatform(origin, webAuthnAuthenticatorAdaptor);
    }

    public static ClientPlatform createClientPlatformWithPackedAuthenticator(Origin origin) {
        var webAuthnAuthenticatorAdaptor = new WebAuthnAuthenticatorAdaptor(EmulatorUtil.PACKED_AUTHENTICATOR);
        return new ClientPlatform(origin, webAuthnAuthenticatorAdaptor);
    }

    public static ClientPlatform createClientPlatformWithTPMAuthenticator(Origin origin) {
        var webAuthnAuthenticatorAdaptor = new WebAuthnAuthenticatorAdaptor(EmulatorUtil.TPM_AUTHENTICATOR);
        return new ClientPlatform(origin, webAuthnAuthenticatorAdaptor);
    }

    public static ClientPlatform createClientPlatformWithFIDOU2FAuthenticator(Origin origin) {
        var webAuthnAuthenticatorAdaptor = new FIDOU2FAuthenticatorAdaptor(EmulatorUtil.FIDO_U2F_AUTHENTICATOR);
        return new ClientPlatform(origin, webAuthnAuthenticatorAdaptor);
    }

    public static ClientPlatform createClientPlatformWithNoneAuthenticator(Origin origin) {
        var webAuthnAuthenticatorAdaptor = new WebAuthnAuthenticatorAdaptor(EmulatorUtil.NONE_ATTESTATION_AUTHENTICATOR);
        return new ClientPlatform(origin, webAuthnAuthenticatorAdaptor);
    }
}
