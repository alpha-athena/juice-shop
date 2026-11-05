/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import semver from 'semver'

import { dependencies } from '../../package.json'

/**
 * No lockfile is committed, so the lowest version a dependency range admits is
 * the version a deployment may actually run. These are globally mounted
 * middleware / data-access packages whose fixed releases fall inside the caret
 * range that was previously declared; the floor must not be lowered below them.
 */
const minimumSafeVersions: Record<string, string> = {
  'body-parser': '1.20.9', // GHSA-27r3-jxmh-p828 (CVE-2026-111181), GHSA-v422-hmwv-36x6
  compression: '1.8.2', // GHSA-vc2v-76pw-4v95
  morgan: '1.12.1', // GHSA-4vj7-5mj6-jm8m, GHSA-jxfw-x594-9x9m, GHSA-9f6g-j8ch-79g4
  sequelize: '6.37.8' // GHSA-6457-6jrx-69cr
}

void describe('dependency floors', () => {
  for (const [name, fixed] of Object.entries(minimumSafeVersions)) {
    void it(`should not allow ${name} below ${fixed}`, () => {
      const range = (dependencies as Record<string, string>)[name]
      assert.ok(range, `${name} is expected to be a declared dependency`)
      const floor = semver.minVersion(range)
      assert.ok(floor, `${name} range "${range}" has no resolvable minimum version`)
      assert.ok(semver.gte(floor, fixed), `${name} range "${range}" admits ${floor.version}, which is below the first fixed release ${fixed}`)
    })
  }
})
