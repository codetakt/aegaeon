const base = require("./commitlint.config.cjs");

// This config is used only for PR titles; commit messages keep the base rules.
// Use the PR author supplied by GitHub, independent of who triggers a rerun.
module.exports = {
  ...base,
  rules: {
    ...base.rules,
    "header-max-length": [
      process.env.PR_AUTHOR_LOGIN === "dependabot[bot]" ? 1 : 2,
      ...base.rules["header-max-length"].slice(1),
    ],
  },
};
