import { spawnSync } from "node:child_process";
import { readdir } from "node:fs/promises";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

// `node --check` only reads its first file argument, so each file is
// checked in its own process. This also works where npm runs scripts
// through cmd.exe, which has no shell loops or globs.
const root = fileURLToPath(new URL("..", import.meta.url));
const directories = ["public", "scripts", "src", "test"];

const files = [];
for (const directory of directories) {
  const entries = await readdir(join(root, directory), {
    recursive: true,
    withFileTypes: true
  });
  for (const entry of entries) {
    if (entry.isFile() && entry.name.endsWith(".js")) {
      files.push(join(entry.parentPath, entry.name));
    }
  }
}

const failed = files.sort().filter((file) => {
  const result = spawnSync(process.execPath, ["--check", file], { stdio: "inherit" });
  return result.status !== 0;
});

for (const file of failed) {
  console.error(`Syntax check failed: ${relative(root, file)}`);
}
console.log(`Checked ${files.length} files, ${failed.length} failed.`);
process.exitCode = failed.length > 0 ? 1 : 0;
