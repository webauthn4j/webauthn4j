
function createCredential(){

    let username = $("#username").val();
    let userHandle = $("#userHandle").val();

    return $.get('/webauthn/attestation/options', null, null, "json").then( options =>{
        let publicKeyCredentialCreationOptions = {
            rp: {
                id: options.rp.id,
                name: options.rp.name
            },
            user: {
                id: base64url.decodeBase64url(userHandle),
                name: username,
                displayName: username
            },
            challenge: base64url.decodeBase64url(options.challenge),
            pubKeyCredParams: options.pubKeyCredParams,
            timeout: options.timeout,
            excludeCredentials: options.excludeCredentials.map(credential => {
                return {
                    type: credential.type,
                    id: base64url.decodeBase64url(credential.id)
                }
            }),
            authenticatorSelection: {
                requireResidentKey: true,
                residentKey: "preferred"
            },
            attestation: options.attestation,
            extensions: options.extensions
        };

        let credentialCreationOptions = {
            publicKey: publicKeyCredentialCreationOptions
        };

        return navigator.credentials.create(credentialCreationOptions);
    });
}

function getCredential(userVerification){
    return $.get('/webauthn/assertion/options', null, null, "json").then(options => {
        let publicKeyCredentialRequestOptions = {
            challenge: base64url.decodeBase64url(options.challenge),
            timeout: options.timeout,
            rpId: options.rpId,
            allowCredentials: options.allowCredentials.map( credential => {
                return {
                    type: credential.type,
                    id: base64url.decodeBase64url(credential.id)
                }
            }),
            userVerification: userVerification,
            extensions: options.extensions
        };

        let credentialRequestOptions = {
            publicKey: publicKeyCredentialRequestOptions
        };

        return navigator.credentials.get(credentialRequestOptions);
    });
}

$(document).ready(function() {


    $('#authenticator').click(function(){
        createCredential().then(function (credential) {
            console.log(credential);
            $('#clientDataJSON').val(base64url.encodeBase64url(credential.response.clientDataJSON));
            $('#attestationObject').val(base64url.encodeBase64url(credential.response.attestationObject));
            $('#clientExtensions').val(JSON.stringify(credential.getClientExtensionResults()));
            $('#authenticator').text('Authenticator registered');
            $('#authenticator').prop('disabled', true);
            $('#submit').prop('disabled', false);
        }).catch(function (e) {
            console.error("Error:%s, Message:%s", e.name, e.message);
        });
    });

    $('#fast-login').click(function(){
        getCredential("required").then(function (credential) {
            console.log(credential);
            $("#credentialId").val(credential.id);
            $("#clientDataJSON").val(base64url.encodeBase64url(credential.response.clientDataJSON));
            $("#authenticatorData").val(base64url.encodeBase64url(credential.response.authenticatorData));
            $("#signature").val(base64url.encodeBase64url(credential.response.signature));
            $("#clientExtensions").val(JSON.stringify(credential.getClientExtensionResults()));
            $('#login-form').submit();
        }).catch(function (e) {
            console.error("Error:%s, Message:%s", e.name, e.message);
        });
        return false;
    });
    $('#retry').click(function(){
        getCredential("preferred").then(function (credential) {
            console.log(credential);
            $("#credentialId").val(credential.id);
            $("#clientDataJSON").val(base64url.encodeBase64url(credential.response.clientDataJSON));
            $("#authenticatorData").val(base64url.encodeBase64url(credential.response.authenticatorData));
            $("#signature").val(base64url.encodeBase64url(credential.response.signature));
            $("#clientExtensions").val(JSON.stringify(credential.getClientExtensionResults()));
            $('#login-form').submit();
        }).catch(function (e) {
            console.error("Error:%s, Message:%s", e.name, e.message);
        });
        return false;
    });

    if($('#login-authenticator-login-view').length>0){
        return getCredential("preferred").then(function (credential) {
            console.log(credential);
            $("#credentialId").val(credential.id);
            $("#clientDataJSON").val(base64url.encodeBase64url(credential.response.clientDataJSON));
            $("#authenticatorData").val(base64url.encodeBase64url(credential.response.authenticatorData));
            $("#signature").val(base64url.encodeBase64url(credential.response.signature));
            $("#clientExtensions").val(JSON.stringify(credential.getClientExtensionResults()));
            $('#login-form').submit();
        }).catch(function (e) {
            console.error("Error:%s, Message:%s", e.name, e.message);
        });
    }
});
