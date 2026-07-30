import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const files = [];

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    const stat = statSync(path);
    if (stat.isDirectory()) {
      if (entry !== 'vendor') {
        walk(path);
      }
      continue;
    }
    if (entry.endsWith('.js')) {
      files.push(path);
    }
  }
}

const explicitTargets = process.argv.slice(2);
if (explicitTargets.length > 0) {
  for (const target of explicitTargets) {
    const stat = statSync(target);
    if (stat.isDirectory()) {
      walk(target);
    } else {
      files.push(target);
    }
  }
} else {
  walk('web/static/js');
}

for (const file of files) {
  // CEREBRUM loads these files as browser ES modules. `node --check file.js`
  // parses a .js file according to the package's default source type, which can
  // accept malformed nested-template syntax that browser module parsing
  // rejects. Force module grammar through stdin so the release gate matches
  // the production loader.
  const source = readFileSync(file, 'utf8');
  const result = spawnSync(
    process.execPath,
    ['--input-type=module', '--check'],
    {
      input: source,
      stdio: ['pipe', 'inherit', 'inherit'],
    },
  );
  if (result.status !== 0) {
    console.error(`ES module syntax check failed: ${file}`);
    process.exit(result.status ?? 1);
  }
}

// Browser-native alerts, confirmations, and prompts break the CEREBRUM theme
// and bypass our accessible dialog behavior. Guard the whole static UI, not
// only app.js, so a later page cannot regress silently.
for (const file of files) {
  const source = readFileSync(file, 'utf8');
  const executableSource = source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/.*$/gm, '');
  const nativeDialog = executableSource.match(/\b(?:window\.)?(alert|confirm|prompt)[ \t]*\(/);
  if (nativeDialog) {
    console.error(`${file} contains native ${nativeDialog[1]}(); use a themed CEREBRUM dialog.`);
    process.exit(1);
  }
}

console.log(`Checked ${files.length} JavaScript files.`);
