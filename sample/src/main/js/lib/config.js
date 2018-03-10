$ = require('jquery');
jQuery = $;

// UpdateViewModel constructor
let Config = function(){
    this.CONTEXT_PATH = $("meta[name='contextPath']").attr("content");
};

Config.prototype.joinPaths = function () {
    return $.makeArray(arguments).join('/').replace("//", "/").replace("//", "/");
};

module.exports = new Config();