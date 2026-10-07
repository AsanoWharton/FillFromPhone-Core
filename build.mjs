import { copyFile, mkdir, rm, writeFile } from "node:fs/promises";
import { faEye, faEyeSlash } from "@fortawesome/free-solid-svg-icons";
import { build } from "esbuild";

function icon(definition) {
  const [width, height, , , path] = definition.icon;
  if (typeof path !== "string") throw new Error(`unexpected icon data for ${definition.iconName}`);
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" role="img"><path fill="#003c71" d="${path}"/></svg>`;
}

const output = new URL("./dist/public/", import.meta.url);
await rm(new URL("./dist/", import.meta.url), { recursive: true, force: true });
await mkdir(new URL("./assets/", output), { recursive: true });

await Promise.all([
  copyFile(new URL("./src/mobile/index.html", import.meta.url), new URL("./mobile.html", output)),
  copyFile(new URL("./src/mobile/styles.css", import.meta.url), new URL("./assets/styles.css", output)),
  copyFile(new URL("./src/shared/header.css", import.meta.url), new URL("./assets/header.css", output)),
  copyFile(new URL("./src/favicon.png", import.meta.url), new URL("./favicon.png", output)),
  copyFile(new URL("./src/security.txt", import.meta.url), new URL("./security.txt", output)),
  copyFile(new URL("./node_modules/@fontsource/space-grotesk/files/space-grotesk-latin-400-normal.woff2", import.meta.url), new URL("./assets/space-grotesk-400.woff2", output)),
  copyFile(new URL("./node_modules/@fontsource/space-grotesk/files/space-grotesk-latin-500-normal.woff2", import.meta.url), new URL("./assets/space-grotesk-500.woff2", output)),
  copyFile(new URL("./node_modules/@fontsource/space-grotesk/files/space-grotesk-latin-700-normal.woff2", import.meta.url), new URL("./assets/space-grotesk-700.woff2", output)),
  copyFile(new URL("./node_modules/@fontsource/sora/files/sora-latin-700-normal.woff2", import.meta.url), new URL("./assets/sora-700.woff2", output)),
  writeFile(new URL("./assets/eye.svg", output), icon(faEye)),
  writeFile(new URL("./assets/eye-slash.svg", output), icon(faEyeSlash)),
  build({
    entryPoints: [new URL("./src/mobile/app.ts", import.meta.url).pathname],
    outfile: new URL("./assets/app.js", output).pathname,
    bundle: true,
    minify: true,
    sourcemap: false,
    target: ["chrome120", "safari17", "firefox121"],
    legalComments: "none"
  })
]);
