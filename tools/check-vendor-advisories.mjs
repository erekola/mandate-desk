// Queries OSV.dev for every component vendor/ethers-6.17.0/sbom.json lists,
// including the four bundled libraries that no automated updater sees
// (package.json declares no dependencies, and .github/dependabot.yml tracks
// only github-actions, so neither npm audit nor Dependabot ever inventories
// vendor/ethers-6.17.0/ or what is bundled inside it) (MD-07). This is the
// runnable form of the manual steps ADVISORIES.md used to only describe in
// prose: nothing here runs automatically, because this repository's own
// tests and CI never reach the network (SECURITY.md, "Tests"). Run it by
// hand before vendoring a new ethers version, and from time to time in
// between, then update the "Last run" line in ADVISORIES.md with the date
// and this script's own summary line.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SBOM_PATH = path.join(HERE, '..', 'vendor', 'ethers-6.17.0', 'sbom.json');
const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';

function readComponents() {
  const sbom = JSON.parse(fs.readFileSync(SBOM_PATH, 'utf8'));
  if (!Array.isArray(sbom.components) || sbom.components.length === 0) {
    throw new Error(`${SBOM_PATH} lists no components.`);
  }
  return sbom.components.map(item => ({ name: item.name, version: item.version }));
}

async function queryOsv(components) {
  const queries = components.map(item => ({ package: { name: item.name, ecosystem: 'npm' }, version: item.version }));
  const response = await fetch(OSV_BATCH_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ queries })
  });
  if (!response.ok) throw new Error(`OSV.dev returned HTTP ${response.status}.`);
  const body = await response.json();
  if (!Array.isArray(body.results) || body.results.length !== components.length) {
    throw new Error('OSV.dev response shape did not match the query count.');
  }
  return body.results;
}

async function main() {
  const components = readComponents();
  console.log(`Checking ${components.length} vendored component(s) from ${path.relative(process.cwd(), SBOM_PATH)} against OSV.dev.`);
  let results;
  try {
    results = await queryOsv(components);
  } catch (error) {
    console.error(`OSV.dev query failed: ${error.message}`);
    console.error('This needs network access. It is never run by this repository\'s own tests or CI (SECURITY.md, "Tests").');
    process.exitCode = 2;
    return;
  }
  let anyVulnerable = false;
  for (let index = 0; index < components.length; index += 1) {
    const component = components[index];
    const vulns = Array.isArray(results[index]?.vulns) ? results[index].vulns : [];
    if (vulns.length === 0) {
      console.log(`OK    ${component.name}@${component.version}: no OSV.dev advisory found.`);
    } else {
      anyVulnerable = true;
      const ids = vulns.map(item => item.id).join(', ');
      console.log(`FOUND ${component.name}@${component.version}: ${vulns.length} OSV.dev advisory/advisories (${ids}).`);
    }
  }
  const runAt = new Date().toISOString();
  console.log('');
  console.log(`Last run: ${runAt}, OSV.dev, ${components.length}/${components.length} components queried, ` +
    `${anyVulnerable ? 'at least one advisory found (see FOUND lines above)' : 'no advisory found for any of them'}.`);
  console.log('Paste the line above into vendor/ethers-6.17.0/ADVISORIES.md under "Last run".');
  if (anyVulnerable) process.exitCode = 1;
}

await main();
