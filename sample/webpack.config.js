let webpack = require('webpack');
let gulpConfig = require('./gulp/config.js');
let path = require('path');

module.exports = {
    webpack: {
        entry: path.join(gulpConfig.js.src, './app.js'),
        output: {
            filename: 'bundle.js'
        },
        resolve: {
            extensions: ['', '.js'],
            root: [ path.resolve('./src/main/js'), path.resolve('./src/main/resources') ]
        },
        module: {
            loaders: [

                { test: /\.css$/, loader: 'style-loader!css-loader' },
                { test: /\.(jpg|png|woff|woff2|eot|ttf|svg)$/, loader: 'url-loader?limit=100000' }
            ]
        },
        plugins: [
            new webpack.ProvidePlugin(
                {
                    jQuery: "jquery",
                    $: "jquery"
                }
            )
        ],
        devtool: 'inline-source-map'
    }

};

