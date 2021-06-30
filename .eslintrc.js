module.exports = {
  root: true,

  extends: ['@metamask/eslint-config'],

  overrides: [
    {
      files: ['*.ts'],
      extends: ['@metamask/eslint-config-typescript'],
    },
    {
      files: ['*.js'],
      extends: ['@metamask/eslint-config-nodejs'],
    },
    {
      files: ['test/index.js'],
      globals: {
        QUnit: true,
      },
    },
  ],

  ignorePatterns: [
    '!.eslintrc.js',
    '!.prettierrc.js',
    'dist/',
    'test/bundle.js',
    'types',
  ],
};
