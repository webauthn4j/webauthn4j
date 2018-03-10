require('static/css/login/login.css');
const base64url = require('base64url');

$ = require('jquery');
jQuery = $;

Config = require('lib/config.js');

// loginViewModel constructor
let LoginViewModel = function(){
    let _this = this;
    $(document).ready(function() {
        //対応するViewがDOMに存在する場合
        if($('#login-login-view').length){
            let searchParams = new URLSearchParams(location.search);
            if(searchParams.has("error")) {
                //nop
            }
            else{
                _this.tryLoginWithSavedPasswordCredential();
            }
            _this.setupEventListeners();
        }
    });

};

LoginViewModel.prototype.setupEventListeners = function () {
    let _this = this;

};

LoginViewModel.prototype.tryLoginWithSavedPasswordCredential = function (){
    let _this = this;

    return _this.getSavedPasswordCredential()
        .then(function (credential) { //succeeded to retrieve credential
            if(typeof credential === "undefined"){
                return Promise.reject("No credential is chosen.");
            }
            else if (credential.type === "password") {
                return _this.loginWithSavedPasswordCredential(credential);
            }
            else {
                return Promise.reject("Unexpected credential type is returned.");
            }
        })
        .catch(function (error) { // fall back to login form
            console.error(error);
        });
};

LoginViewModel.prototype.getSavedPasswordCredential = function (){
    let _this = this;

    if(typeof PasswordCredential === "undefined"){
        return Promise.reject("Credential Management API is not supported.");
    }

    return navigator.credentials.get({
        mediation: "optional",
        password: true
    });
};

LoginViewModel.prototype.loginWithSavedPasswordCredential = function (credential) {
    let _this = this;

    let username = credential.id;
    let password = credential.password;

    _this.loginByFormSubmission(username, password);
};

LoginViewModel.prototype.loginByFormSubmission = function (username, password) {
    let loginForm = $("#login-form");
    loginForm.find("input[name='username']").val(username);
    loginForm.find("input[name='rawPassword']").val(password);
    loginForm.submit();
};

module.exports = new LoginViewModel();