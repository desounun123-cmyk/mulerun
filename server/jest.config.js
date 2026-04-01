/** @type {import('jest').Config} */
module.exports = {
  testPathIgnorePatterns: [
    'helpers\\.js$',
  ],
  transform: {
    '\\.[jt]sx?$': ['babel-jest', { sourceType: 'script' }],
  },
};
