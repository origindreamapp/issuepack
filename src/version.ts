import { createRequire } from "node:module";

export const NAME = "IssuePack";

const packageMetadata = createRequire(import.meta.url)("../package.json") as {
  version?: unknown;
};
if (typeof packageMetadata.version !== "string") {
  throw new Error("IssuePack package metadata is missing a version.");
}

export const VERSION = packageMetadata.version;
