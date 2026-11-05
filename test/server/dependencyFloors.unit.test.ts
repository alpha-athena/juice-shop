/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import semver from 'semver'

import { dependencies } from '../../package.json'

/*
 * No lockfile is committed (.npmrc sets package-lock=false), so the floor of
 * each range in package.json is the only thing the repository controls about
 * which version a deployment installs. These middlewares handle every request
 * (body-parser, compression, morgan) or every database query (sequelize) and
 * are not part of any challenge, so their floors must not admit a release with
 * a published advisory.
 */
const fixedFloors: Record<string, { fixed: string, advisories: string[] }> = {
  'body-parser': { fixed: '1.20.9', advisories: ['GHSA-27r3-jxmh-p828', 'GHSA-v422-hmwv-36x6'] },
  compression: { fixed: '1.8.2', advisories: ['GHSA-vc2v-76pw-4v95'] },
  morgan: { fixed: '1.12.1', advisories: ['GHSA-4vj7-5mj6-jm8m', 'GHSA-jxfw-x594-9x9m', 'GHSA-9f6g-j8ch-79g4'] },
  sequelize: { fixed: '6.37.8', advisories: ['GHSA-6457-6jrx-69cr'] }
}

void describe('dependency floors', () => {
  for (const [name, { fixed, advisories }] of Object.entries(fixedFloors)) {
    void it(`${name} range must not admit a version below ${fixed} (${advisories.join(', ')})`, () => {
      const range = (dependencies as Record<string, string>)[name]
      assert.ok(range, `${name} is expected to be a dependency`)
      const floor = semver.minVersion(range)
      assert.ok(floor, `${name} range "${range}" has no minimum version`)
      assert.ok(semver.gte(floor, fixed), `${name} range "${range}" admits ${floor.version}, below the first fixed release ${fixed}`)
    })
  }
})
