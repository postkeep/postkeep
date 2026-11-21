// Build-time data (commands run from site/): copy, settings and Cargo.toml repository identity.
import { readFileSync } from "node:fs";
import copy from "../data/copy.json";
import settings from "../data/site.json";

const repository = /^repository = "([^"]+)"$/m.exec(readFileSync("../Cargo.toml", "utf8"))?.[1];
if (!repository) throw new Error("Cargo.toml has no repository URL");

const SITE = {
  ...settings,
  source: {
    ...settings.source,
    web: repository,
    clone: `${repository}.git`,
    issues: `${repository}/issues`,
    releases: `${repository}/tags`,
  },
};

export { copy, SITE };
