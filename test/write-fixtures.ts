/*
 * Generates the fixtures that cannot be committed, then exits.
 *
 * Run by the `test` script before `node --test`. See test/credentials-fixture.ts
 * for why the credential fixture is assembled rather than stored.
 */

import { writeCredentialsFixture } from './credentials-fixture.js';

const written = writeCredentialsFixture();
if (process.argv.includes('--verbose')) {
  console.log(`generated ${written}`);
}
