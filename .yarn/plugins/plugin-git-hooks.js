const { execute } = require('@yarnpkg/shell');

const afterAllInstalled = async () => {
  const exitCode = await execute('yarn simple-git-hooks');

  if (exitCode !== 0) {
    // We have to use `process.exit` here rather than setting `process.exitCode`
    // because Yarn will override any exit code set in this hook.
    // eslint-disable-next-line node/no-process-exit
    process.exit(exitCode);
  }
};

module.exports = {
  name: 'plugin-git-hooks',
  factory: () => {
    return {
      default: {
        hooks: {
          afterAllInstalled
        }
      }
    };
  }
};
