import semver from 'semver';
// build-time only: fail the build on an unsupported Node version
if (!semver.satisfies(process.versions.node, '>=20')) throw new Error('Node 20+ required');
export default {
  output: 'standalone',
  serverExternalPackages: ['js-yaml'],
  productionBrowserSourceMaps: true,
  experimental: { serverSourceMaps: true },
};
