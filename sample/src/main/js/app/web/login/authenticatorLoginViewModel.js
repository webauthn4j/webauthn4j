require('static/css/login/login.css');
const base64url = require('base64url');

$ = require('jquery');
jQuery = $;

Config = require('lib/config.js');

// authenticatorLoginViewModel constructor
let AuthenticatorLoginViewModel = function(){
    let _this = this;
    $(document).ready(function() {
        //対応するViewがDOMに存在する場合
        if($('#login-authenticator-login-view').length){
            _this.setupEventListeners();
            _this.tryLoginWithPublicKeyCredential();
        }
    });

};

AuthenticatorLoginViewModel.prototype.setupEventListeners = function () {
    let _this = this;

    $('#webauthn-login').click(function () {
        _this.tryLoginWithPublicKeyCredential();
    });
};

AuthenticatorLoginViewModel.prototype.tryLoginWithPublicKeyCredential = function (){
    let _this = this;

    return _this.getPublicKeyCredential()
        .then(function (credential) { //succeeded to retrieve credential
            if (credential.type === "public-key") {
                return _this.loginWithPublicKeyCredential(credential);
            }
            else {
                console.error("Unexpected credential type is returned.");
            }
        })
        .catch(function (error) { // fall back to login form
            $("#gesture-request-modal").modal('hide');
        });
};

AuthenticatorLoginViewModel.prototype.getPublicKeyCredential = function (){
    let _this = this;

    if(typeof navigator.credentials === "undefined"){
        return Promise.reject("Credential Management API is not supported.");
    }

    $("#gesture-request-modal").modal('show');

    let challenge = this.loadChallenge();
    return this.loadCredentialIds().then(function(credentialIds){
        let allowCredentials = credentialIds.map( credentialId => {
            return {
                id: credentialId,
                type: "public-key",
                transports: ["usb", "nfc", "ble"]
            }
        });

        let publicKeyCredentialRequestOptions = {
            challenge: challenge,
            //timeout: null,
            //rpId: null,
            allowCredentials: allowCredentials,
            userVerification: "preferred",
            extensions: {}
        };

        return navigator.credentials.get({
            mediation: "required",
            publicKey: publicKeyCredentialRequestOptions
        }).then(function(credential){
            if(typeof credential === "undefined"){
                return Promise.reject("No credential is chosen.");
            }
            else{
                return Promise.resolve(credential);
            }
        });
    });

};

AuthenticatorLoginViewModel.prototype.loginWithPublicKeyCredential = function (credential) {
    let _this = this;

    let credentialId = credential.id;
    let clientData = credential.response.clientDataJSON;
    let authenticatorData = credential.response.authenticatorData;
    let signature = credential.response.signature;

    _this.loginByFormSubmission(null, null, credentialId, clientData, authenticatorData, signature);
};

AuthenticatorLoginViewModel.prototype.loginByFormSubmission = function (username, password, credentialId, clientData, authenticatorData, signature) {
    let loginForm = $("#login-form");
    loginForm.find("input[name='username']").val(username);
    loginForm.find("input[name='rawPassword']").val(password);
    loginForm.find("input[name='credentialId']").val(credentialId);
    loginForm.find("input[name='collectedClientData']").val(base64url.encode(clientData));
    loginForm.find("input[name='authenticatorData']").val(base64url.encode(authenticatorData));
    loginForm.find("input[name='signature']").val(base64url.encode(signature));
    loginForm.submit();
};


AuthenticatorLoginViewModel.prototype.loadCredentialIds = function () {
    return fetch("/webauthn/metadata",  //TODO
    {
        credentials: 'include'
    })
    .then(response => {
        return response.json().then(function(json){
            return json.map(metadata => base64url.toBuffer(metadata["credentialId"]));
        });
    });
};

AuthenticatorLoginViewModel.prototype.loadChallenge = function () {
    let challengeBase64 = $("meta[name='_challenge']").attr("content");
    return base64url.toBuffer(challengeBase64);
};

module.exports = new AuthenticatorLoginViewModel();