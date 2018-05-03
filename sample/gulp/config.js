let path = require('path');

let src = path.join(__dirname, '../src');
let dst = path.join(__dirname, '../build');

module.exports = {
    dst: dst,

    js: {
        src: path.join(src, './main/js'),
        dst: path.join(dst, './resources/main/static/js'),
        uglify: false
    }
};