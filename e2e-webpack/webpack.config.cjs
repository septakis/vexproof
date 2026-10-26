const { CycloneDxWebpackPlugin } = require('@cyclonedx/webpack-plugin');
module.exports = { mode: 'production', entry: './app.js', target: 'web', output: { path: __dirname + '/dist', filename: 'app.js' },
  plugins: [new CycloneDxWebpackPlugin({ specVersion: '1.6', outputLocation: './cyclonedx', includeWellknown: false })] };
