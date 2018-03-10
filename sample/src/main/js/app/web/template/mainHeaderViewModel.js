$ = require('jquery');
jQuery = $;

Config = require('lib/config.js');

// loginViewModel constructor
let MainHeaderViewModel = function(){
    let _this = this;
    $(document).ready(function() {
        //対応するViewがDOMに存在する場合
        if($('#main-header-view').length){
            _this.setupEventListeners();
        }
    });
};

MainHeaderViewModel.prototype.onLogoutFormSubmit = function (e){
    navigator.credentials.preventSilentAccess();
};

MainHeaderViewModel.prototype.setupEventListeners = function () {
    let _this = this;
    $('#logout-form').on('submit', function(e){
        _this.onLogoutFormSubmit(e);
    });

};

module.exports = new MainHeaderViewModel();
