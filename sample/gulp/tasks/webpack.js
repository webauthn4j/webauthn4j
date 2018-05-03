// @file webpack.js
let gulp = require('gulp');
let webpack = require('webpack-stream');
let gulpConfig = require('../config.js');
let webpackConfig = require('../../webpack.config.js');

// タスク名はファイル名と同じにしておくと見通しが良い
gulp.task('webpack', function () {
    gulp.src(webpackConfig.webpack.entry)
        .pipe(webpack(webpackConfig.webpack))
        .pipe(gulp.dest(gulpConfig.js.dst));
});
