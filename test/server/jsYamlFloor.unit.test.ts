/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import path from 'path'
import fs from 'fs'
import semver from 'semver'

// routes/fileUpload.ts runs yaml.load() over the raw body of the unauthenticated
// POST /file-upload. js-yaml versions below 3.15.2 are listed against
// GHSA-mh29-5h37-fv8m, GHSA-h67p-54hq-rp68, GHSA-52cp-r559-cp3m,
// GHSA-5p4m-2wfm-xmqj and GHSA-2883-xcg3-v3hh. This test keeps the declared
// range from ever resolving to one of them again.
const FIRST_FIXED_VERSION = '3.15.2'

const manifest = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../../package.json'), 'utf8'))
const declaredRange: string = manifest.dependencies['js-yaml']

void describe('js-yaml dependency floor', () => {
  void it(`should declare a range in package.json that cannot resolve below ${FIRST_FIXED_VERSION}`, () => {
    const floor = semver.minVersion(declaredRange)
    assert.notEqual(floor, null, `"${declaredRange}" is not a valid semver range`)
    assert.ok(semver.gte(floor as semver.SemVer, FIRST_FIXED_VERSION), `package.json pins js-yaml "${declaredRange}", whose floor ${String(floor)} admits versions with open advisories; the floor must be >= ${FIRST_FIXED_VERSION}`)
  })

  void it(`should have an installed js-yaml of at least ${FIRST_FIXED_VERSION}`, () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const installed: string = require('js-yaml/package.json').version
    assert.ok(semver.gte(installed, FIRST_FIXED_VERSION), `installed js-yaml ${installed} is below ${FIRST_FIXED_VERSION}; run npm install`)
  })
})
