package com.webauthn4j.async;

import com.webauthn4j.async.verifier.AuthenticationDataAsyncVerifier;
import com.webauthn4j.async.verifier.CustomAuthenticationAsyncVerifier;
import com.webauthn4j.converter.AuthenticationExtensionsClientOutputsConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.CollectedClientDataConverter;
import com.webauthn4j.converter.exception.DataConversionException;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.util.AssertUtil;
import com.webauthn4j.util.CompletionStageUtil;
import com.webauthn4j.verifier.exception.VerificationException;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.core.type.TypeReference;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletionStage;

public class WebAuthnAuthenticationAsyncManager {

    // ~ Instance fields
    // ================================================================================================
    private final Logger logger = LoggerFactory.getLogger(WebAuthnAuthenticationAsyncManager.class);

    private final CollectedClientDataConverter collectedClientDataConverter;
    private final AuthenticatorDataConverter authenticatorDataConverter;
    private final AuthenticationExtensionsClientOutputsConverter authenticationExtensionsClientOutputsConverter;

    private final AuthenticationDataAsyncVerifier authenticationDataAsyncVerifier;

    private final ObjectConverter objectConverter;

    public WebAuthnAuthenticationAsyncManager(
            @NotNull List<CustomAuthenticationAsyncVerifier> customAuthenticationAsyncVerifiers,
            @NotNull ObjectConverter objectConverter) {
        AssertUtil.notNull(customAuthenticationAsyncVerifiers, "customAuthenticationAsyncVerifiers must not be null");
        AssertUtil.notNull(objectConverter, "objectConverter must not be null");

        this.authenticationDataAsyncVerifier = new AuthenticationDataAsyncVerifier(customAuthenticationAsyncVerifiers);

        this.collectedClientDataConverter = new CollectedClientDataConverter(objectConverter);
        this.authenticatorDataConverter = new AuthenticatorDataConverter(objectConverter);
        this.authenticationExtensionsClientOutputsConverter = new AuthenticationExtensionsClientOutputsConverter(objectConverter);
        this.objectConverter = objectConverter;
    }

    public WebAuthnAuthenticationAsyncManager(
            @NotNull List<CustomAuthenticationAsyncVerifier> customAuthenticationVerifiers) {
        this(customAuthenticationVerifiers, new ObjectConverter());
    }

    public WebAuthnAuthenticationAsyncManager() {
        this(Collections.emptyList(), new ObjectConverter());
    }

    @SuppressWarnings("squid:S1130")
    public CompletionStage<AuthenticationData> parse(String authenticationResponseJSON) {
        return CompletionStageUtil
                .supply(()-> objectConverter.getJsonMapper().readValue(authenticationResponseJSON, new TypeReference<PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput>>() {}))
                .thenApply( publicKeyCredential -> {
            byte[] credentialId = publicKeyCredential.getRawId();
            byte[] userHandle = publicKeyCredential.getResponse().getUserHandle();

            byte[] clientDataBytes = publicKeyCredential.getResponse().getClientDataJSON();
            CollectedClientData collectedClientData = clientDataBytes == null ? null : collectedClientDataConverter.convert(clientDataBytes);

            byte[] authenticatorDataBytes = publicKeyCredential.getResponse().getAuthenticatorData();
            AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData = authenticatorDataBytes == null ? null : authenticatorDataConverter.convert(authenticatorDataBytes);

            AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions = publicKeyCredential.getClientExtensionResults();

            byte[] signature = publicKeyCredential.getResponse().getSignature();

            return new AuthenticationData(
                    credentialId,
                    userHandle,
                    authenticatorData,
                    authenticatorDataBytes,
                    collectedClientData,
                    clientDataBytes,
                    clientExtensions,
                    signature
            );
        });
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull CompletionStage<AuthenticationData> parse(@NotNull AuthenticationRequest authenticationRequest) {
        return CompletionStageUtil.supply(()->{
            AssertUtil.notNull(authenticationRequest, "authenticationRequest must not be null");

            logger.trace("Parse: {}", authenticationRequest);

            byte[] credentialId = authenticationRequest.getCredentialId();
            byte[] signature = authenticationRequest.getSignature();
            byte[] userHandle = authenticationRequest.getUserHandle();
            byte[] clientDataBytes = authenticationRequest.getClientDataJSON();
            CollectedClientData collectedClientData =
                    clientDataBytes == null ? null : collectedClientDataConverter.convert(clientDataBytes);
            byte[] authenticatorDataBytes = authenticationRequest.getAuthenticatorData();
            AuthenticatorData<AuthenticationExtensionAuthenticatorOutput> authenticatorData =
                    authenticatorDataBytes == null ? null : authenticatorDataConverter.convert(authenticatorDataBytes);
            AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput> clientExtensions =
                    authenticationRequest.getClientExtensionsJSON() == null ? null : authenticationExtensionsClientOutputsConverter.convert(authenticationRequest.getClientExtensionsJSON());

            return new AuthenticationData(
                    credentialId,
                    userHandle,
                    authenticatorData,
                    authenticatorDataBytes,
                    collectedClientData,
                    clientDataBytes,
                    clientExtensions,
                    signature
            );
        });
    }

    public @NotNull CompletionStage<AuthenticationData> verify(
            @NotNull String authenticationResponseJSON,
            @NotNull AuthenticationParameters authenticationParameters) throws DataConversionException, VerificationException {
        return parse(authenticationResponseJSON).thenCompose(authenticationData-> verify(authenticationData, authenticationParameters));
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull CompletionStage<AuthenticationData> verify(
            @NotNull AuthenticationRequest authenticationRequest,
            @NotNull AuthenticationParameters authenticationParameters) {
        return parse(authenticationRequest).thenCompose(authenticationData -> verify(authenticationData, authenticationParameters));
    }

    @SuppressWarnings("squid:S1130")
    public @NotNull CompletionStage<AuthenticationData> verify(
            @NotNull AuthenticationData authenticationData,
            @NotNull AuthenticationParameters authenticationParameters) {
        logger.trace("Verify: {}, {}", authenticationData, authenticationParameters);
        return authenticationDataAsyncVerifier.verify(authenticationData, authenticationParameters);
    }

    public @NotNull AuthenticationDataAsyncVerifier getAuthenticationDataAsyncVerifier() {
        return authenticationDataAsyncVerifier;
    }
}
