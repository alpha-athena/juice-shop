/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import request from 'supertest'
import type { Express } from 'express'
import { createTestApp } from './helpers/setup'

let app: Express

before(async () => {
  const result = await createTestApp()
  app = result.app
}, { timeout: 60000 })

void describe('/rest/products/search', () => {
  void it('GET product search is no longer served, so no query string reaches the database', async () => {
    const res = await request(app)
      .get("/rest/products/search?q=')) UNION SELECT id, email, password, '4', '5', '6', '7', '8', '9' FROM Users--")
    assert.equal(res.status, 404)
  })
})
