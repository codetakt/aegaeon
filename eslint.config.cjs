const js = require("@eslint/js");
const eslintConfigPrettier = require("eslint-config-prettier");
const globals = require("globals");
const tseslint = require("typescript-eslint");

const tsFiles = [
  "scripts/check-strict-types.ts",
  "scripts/check-workflow-inventory.ts",
  "scripts/sdk/check_sdk_strict_types.ts",
  "scripts/sdk/tools-src/check-strict-types.ts",
  "tests/verified_core_wasm/root_strict_types_policy_test.ts",
  "tests/verified_core_wasm/strict_types_policy_test.ts",
  "tests/verified_core_wasm/workflow_inventory_policy_test.ts",
];

const typedConfigs = tseslint.configs.strictTypeChecked.map((config) => ({
  ...config,
  files: config.files ?? tsFiles,
}));

module.exports = tseslint.config(
  {
    ignores: [
      "artifacts/**",
      "generated/**",
      "node_modules/**",
      "result/**",
      "result-dev/**",
      "result-server/**",
      "target/**",
    ],
  },
  {
    ...js.configs.recommended,
    files: ["**/*.{js,cjs,mjs}"],
    languageOptions: {
      ...js.configs.recommended.languageOptions,
      globals: {
        ...globals.node,
      },
    },
  },
  ...typedConfigs,
  {
    files: tsFiles,
    languageOptions: {
      parserOptions: {
        project: ["./tsconfig.json"],
        tsconfigRootDir: __dirname,
      },
      globals: {
        ...globals.node,
      },
    },
    rules: {
      "@typescript-eslint/consistent-type-imports": [
        "error",
        {
          fixStyle: "separate-type-imports",
          prefer: "type-imports",
        },
      ],
      "@typescript-eslint/no-misused-promises": [
        "error",
        {
          checksVoidReturn: {
            arguments: false,
          },
        },
      ],
    },
  },
  eslintConfigPrettier,
);
