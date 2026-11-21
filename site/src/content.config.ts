// The docs pages, one page per file at /docs/<path>/: the site's own Markdown and MDX under src/content/docs/docs/,
// and the pages scripts/docs.ts writes from the repository's docs/ folder into src/content/repo/.
import { defineCollection } from "astro:content";
import { glob } from "astro/loaders";
import { z } from "astro/zod";

const schema = z.object({
  title: z.string(),
  description: z.string(),
});

export const collections = {
  docs: defineCollection({ loader: glob({ pattern: "**/*.{md,mdx}", base: "./src/content/docs/docs" }), schema }),
  repo: defineCollection({ loader: glob({ pattern: "**/*.md", base: "./src/content/repo" }), schema }),
};
