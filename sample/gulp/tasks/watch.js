var gulp = require('gulp');

gulp.task("watch", function() {
    var targets = [
        './src/main/resources/**/*',
        './src/main/js/**/*',
    ];
    gulp.watch(targets, ['build']);
});