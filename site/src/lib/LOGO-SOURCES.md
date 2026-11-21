# Agent app, mail provider and host logos

Each file in `public/assets/logos/` was downloaded from its owner's source below, on 10 Oct 2026 unless its row gives another date, and checked byte for byte against it. None is redrawn or edited; the one resampled file says so.

The names and logos are trademarks of their owners. The site uses them only beside the name of the app, mailbox or service they stand for (nominative use), with its artwork at 40 px or smaller. No endorsement is implied. Each row's terms name the owner, which the independence line in README.md and the site's footer must list (`checks/facts.test.ts`).

How the site shows them (`src/lib/logos.js` lists the files):

- Every logo is an unaltered `<img>` file in its owner's colours.
- **Marks with a file per surface** (ChatGPT, Grok, Cursor, iCloud, GitHub, Docker) show the one for the page's theme.

The OpenAI files carry more clear space than the others (their artwork spans about half of the file's width), so `src/styles/home.css` draws them larger to match the rest by eye, at 28 or 32 px.

| File | Shown for | Source | Terms and notes |
| --- | --- | --- | --- |
| `claude-icon.svg` | Claude | Anthropic press kit, https://www.anthropic.com/press-kit (zip): `Anthropic logos/Claude logos/4 Claude icon/SVG/ClaudeIcon-Rounded.svg`, downloaded on 2 Nov 2026 | Anthropic's trademark; no logo terms found. |
| `openai-blossom-black.svg`, `openai-blossom-white.svg` | ChatGPT (black on light surfaces, white on dark ones) | OpenAI logo pack, https://cdn.openai.com/brand/openai-logos.zip: `OpenAI-logos/SVGs/OAI_OpenAI-Blossom_Black.svg` and `OAI_OpenAI-Blossom_White.svg`, downloaded on 3 Nov 2026 | OpenAI brand guidelines, https://openai.com/brand/ |
| `grok-dark.svg`, `grok-light.svg` | Grok (dark on light surfaces, light on dark ones) | xAI brand assets, https://data.x.ai/logos/SpaceXAI_Grok_Assets.zip (`Grok_Logomark_Dark.svg` and `Grok_Logomark_Light.svg`), downloaded on 3 Nov 2026 | xAI brand guidelines, https://x.ai/legal/brand-guidelines: use the files exactly as provided, no implied endorsement. |
| `cursor-cube-2d-light.svg`, `cursor-cube-2d-dark.svg` | Cursor (dark on light surfaces, light on dark ones) | Cursor's brand page, https://cursor.com/brand (`cursor-brand-assets.zip`): `General Logos/Cube/SVG/CUBE_2D_LIGHT.svg` and `CUBE_2D_DARK.svg`, downloaded on 3 Nov 2026 | Anysphere's trademark; Cursor's brand page. |
| `vscode.svg` | VS Code | https://code.visualstudio.com/assets/branding/visual-studio-code-icons.zip | Microsoft's trademark; Visual Studio Code brand guidelines, https://code.visualstudio.com/brand. Full colour. |
| `icloud-light.png`, `icloud-dark.png` | iCloud Mail | iCloud's own icons, https://www.icloud.com/system/icloud.com/2640Build24/favicons/default-favicon-light-180x180.png and `default-favicon-dark-180x180.png`, downloaded on 2 Nov 2026 | Apple's trademark; Guidelines for Using Apple Trademarks and Copyrights, https://www.apple.com/legal/intellectual-property/guidelinesfor3rdparties.html |
| `gmail.svg` | Gmail | https://fonts.gstatic.com/s/i/productlogos/gmail_2020q4/v8/192px.svg | Google brand terms, https://about.google/brand-resource-center/ |
| `outlook-icon-fy26.svg` | Outlook.com and Microsoft 365 | The icon on Microsoft's Outlook product page, https://www.microsoft.com/content/dam/microsoft/bade/images/icons/en-us/m365-app-icons-fy26/Outlook-Icon-FY26.svg, downloaded on 2 Nov 2026 | Microsoft Trademark and Brand Guidelines, https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks |
| `fastmail-icon.png` | Fastmail | Fastmail's logo kit, https://www.fastmail.com/assets/brand/Fastmail_Logos.zip: `Fastmail_Logos_RGB/FM-Icon-RGB.png` (3073 px), downloaded on 2 Nov 2026. **Resampled** evenly to 192 px (Lanczos); nothing else changed. | Fastmail logo guidelines, https://www.fastmail.com/assets/brand/Fastmail-Logo-Guidelines-March-2019-V1.pdf |
| `yahoo.png` | Yahoo Mail | Yahoo's own app icon, https://s.yimg.com/cv/apiv2/icons/yahoo.png | Yahoo's brand kit is a private Brandfolder that needs approval, so this is the icon Yahoo serves publicly (512 × 512). |
| `github-mark-black.svg`, `github-mark-white.svg` | GitHub, beside the source link (black on light surfaces, white on dark ones) | GitHub logo pack, https://brand.github.com/GitHub_Logos.zip: `GitHub Logos/SVG/GitHub_Invertocat_Black.svg` and `GitHub_Invertocat_White.svg`, downloaded on 18 Nov 2026 | GitHub logo guidelines, https://github.com/logos. Unaltered files. |
| `docker-mark-ocean-blue.svg`, `docker-mark-white.svg` | Docker Hub, beside the image link (blue on light surfaces, white on dark ones) | Docker media kit, https://www.docker.com/static/Docker-Logos-1.zip (from https://www.docker.com/company/newsroom/media-resources/): `docker-logos/SVG/`, downloaded on 2 Nov 2026 | Docker's trademark guidelines, https://www.docker.com/legal/trademark-guidelines/ |

## Kept neutral

| Slot | Shown instead | Why |
| --- | --- | --- |
| Your own IMAP server | postkeep's server icon | Not a brand. |
