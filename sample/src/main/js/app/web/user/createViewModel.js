const base64url = require('base64url');

$ = require('jquery');
jQuery = $;

Config = require('lib/config.js');

// loginViewModel constructor
let UserCreateViewModel = function(){
    let _this = this;
    this._authenticatorListIndex = 0;
    $(document).ready(function() {
        //対応するViewがDOMに存在する場合
        if($('#user-create-view').length){
            _this.setupEventListeners();
        }
    });
};

UserCreateViewModel.prototype.addCredential = function (){
    let _this = this;
    let challengeBase64 = $("meta[name='_challenge']").attr("content");
    let challenge  = base64url.toBuffer(challengeBase64);
    let userHandle = base64url.toBuffer($('#userHandle').val());

    let makePublicKeyCredentialOptions = {
        // Relying Party:
        rp: {
            name: "spring-security-webauthn sample"
        },
        // User:
        user: {
            id: userHandle,
            name: $('#emailAddress').val(),
            displayName: $('#firstName').val() + " " + $('#lastName').val(),
            icon: null
        },
        challenge: challenge,
        pubKeyCredParams: [
            {
                alg: -7,
                type: "public-key",
            }
        ],
        //timeout
        //excludeCredentials = []
        //authenticatorSelection
        attestation: "none",
        //extensions
    };
    let credentialCreationOptions = {
        publicKey: makePublicKeyCredentialOptions
    };

    $("#gesture-request-modal").modal('show');
    navigator.credentials.create(credentialCreationOptions).then(function(credential){
        $("#gesture-request-modal").modal('hide');
        console.log(credential);
        _this.saveCredentialId(credential.rawId);
        _this.addCredentialForm(userHandle, credential.response.clientDataJSON, credential.response.attestationObject);
    }).catch(function(error){
        $("#gesture-request-modal").modal('hide');
        return Promise.reject(error);
    });
};

UserCreateViewModel.prototype.saveCredentialId = function (credentialId) {
    let encodedId = base64url.encode(credentialId);
    localStorage.setItem('net.sharplab.springframework.security.webauthn.credentialId', encodedId);
};

UserCreateViewModel.prototype.addCredentialForm = function (userHandle, clientData, attestationObject) {
    let _this = this;

    $('<tr />', { class: "authenticator-item" })
        .append($('<td />')
            .append($('<input />', { type: "hidden", name: "authenticators["+ _this._authenticatorListIndex +"].userHandle", value: base64url.encode(userHandle)}))
            .append($('<input />', { type: "text", name: "authenticators["+ _this._authenticatorListIndex +"].name", value: "", class: "form-control input", placeholder: "Authenticator Name"}))
            .append($('<input />', { type: "hidden", name: "authenticators["+ _this._authenticatorListIndex +"].clientData", value: base64url.encode(clientData)}))
            .append($('<input />', { type: "hidden", name: "authenticators["+ _this._authenticatorListIndex +"].attestationObject", value: base64url.encode(attestationObject)}))
        )
        .append($('<td />')
            .append(
                $('<button type="button" class="btn btn-box-tool remove-button"><i class="fa fa-remove"></i></button>')
                    .on('click', function(e){$(e.target).closest('tr.authenticator-item').remove();})
            )
        )
        .appendTo($('#authenticator-list'));

    _this._authenticatorListIndex++;
};

UserCreateViewModel.prototype.setupEventListeners = function () {
    let _this = this;
    $('#add-credential-button').on('click', function(e){
        _this.addCredential();
    });
    $('#authenticator-list .remove-button').on('click', function(){
        $(this).closest('tr.authenticator-item').remove();
    });
};

module.exports = new UserCreateViewModel();
