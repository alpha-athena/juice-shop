/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { profileImageUrlUpload, isCloudMetadataAddress } from '../../routes/profileImageUrlUpload'
import { UserModel } from '../../models/user'
import * as security from '../../lib/insecurity'

void describe('profileImageUrlUpload', () => {
  void describe('isCloudMetadataAddress', () => {
    void describe('should be true for link-local and cloud metadata addresses', () => {
      const addresses = [
        '169.254.169.254', // AWS/GCP/Azure instance metadata
        '169.254.170.2', // ECS task metadata
        '169.254.0.1',
        '::ffff:169.254.169.254', // IPv4-mapped IPv6
        '::ffff:a9fe:a9fe', // IPv4-mapped IPv6, hex form
        'fd00:ec2::254', // AWS IMDS over IPv6
        'fd00:ec2:0:0:0:0:0:254',
        'fe80::1' // IPv6 link-local
      ]
      addresses.forEach(address => {
        void it(address, () => {
          assert.equal(isCloudMetadataAddress(address), true)
        })
      })
    })

    void describe('should be false for other addresses', () => {
      const addresses = [
        '127.0.0.1', // needed by the "ssrfChallenge"
        '::1',
        '::ffff:127.0.0.1',
        '10.0.0.1',
        '192.168.1.1',
        '169.253.255.255',
        '169.255.0.0',
        '93.184.216.34',
        '2606:2800:220:1:248:1893:25c8:1946',
        'not-an-ip'
      ]
      addresses.forEach(address => {
        void it(address, () => {
          assert.equal(isCloudMetadataAddress(address), false)
        })
      })
    })
  })

  void describe('handler', () => {
    const originalFetch = globalThis.fetch
    let req: any
    let res: any
    let next: any
    let fetchMock: any
    let updateMock: any

    beforeEach(() => {
      req = { body: {}, cookies: { token: 'token' }, app: { locals: {} }, socket: { remoteAddress: '127.0.0.1' } }
      res = { location: mock.fn(), redirect: mock.fn() }
      next = mock.fn()
      // a non-OK response keeps the handler off the filesystem and on the existing "store the link" fallback
      fetchMock = mock.fn(async () => new Response(null, { status: 404 }))
      globalThis.fetch = fetchMock
      updateMock = mock.fn(async (data: any) => data)
      mock.method(security.authenticatedUsers, 'get', () => ({ data: { id: 1 } }))
      mock.method(UserModel, 'findByPk', async () => ({ update: updateMock }))
    })

    afterEach(() => {
      globalThis.fetch = originalFetch
      mock.restoreAll()
    })

    const metadataUrls = [
      'http://169.254.169.254/latest/meta-data/iam/security-credentials/', // AWS IMDS
      'http://169.254.170.2/v2/credentials/', // ECS task metadata
      'http://[fd00:ec2::254]/latest/meta-data/', // AWS IMDS over IPv6
      'http://2852039166/latest/meta-data/' // 169.254.169.254 as a decimal integer
    ]
    metadataUrls.forEach(url => {
      void it(`should not fetch ${url} and fall back to storing the link`, async () => {
        req.body.imageUrl = url

        await profileImageUrlUpload()(req, res, next)

        assert.equal(fetchMock.mock.calls.length, 0)
        assert.equal(updateMock.mock.calls[0].arguments[0].profileImage, url)
        assert.equal(res.redirect.mock.calls.length, 1)
        assert.equal(next.mock.calls.length, 0)
      })
    })

    void it('should still fetch localhost so the "ssrfChallenge" keeps working', async () => {
      req.body.imageUrl = 'http://localhost:3000/solve/challenges/server-side?key=test'

      await profileImageUrlUpload()(req, res, next)

      assert.equal(fetchMock.mock.calls.length, 1)
      assert.equal(fetchMock.mock.calls[0].arguments[0], 'http://localhost:3000/solve/challenges/server-side?key=test')
      assert.equal(req.app.locals.abused_ssrf_bug, true)
      assert.equal(res.redirect.mock.calls.length, 1)
    })

    void it('should still fetch loopback IP addresses', async () => {
      req.body.imageUrl = 'http://127.0.0.1:3000/photo.jpg'

      await profileImageUrlUpload()(req, res, next)

      assert.equal(fetchMock.mock.calls.length, 1)
    })

    void it('should not follow redirects, so a redirect cannot reach the metadata service', async () => {
      req.body.imageUrl = 'http://127.0.0.1:3000/photo.jpg'

      await profileImageUrlUpload()(req, res, next)

      assert.equal(fetchMock.mock.calls[0].arguments[1].redirect, 'manual')
    })

    void it('should fall back to storing a scheme-less URL as before', async () => {
      req.body.imageUrl = 'cataas.com/cat'

      await profileImageUrlUpload()(req, res, next)

      assert.equal(updateMock.mock.calls[0].arguments[0].profileImage, 'cataas.com/cat')
      assert.equal(res.redirect.mock.calls.length, 1)
      assert.equal(next.mock.calls.length, 0)
    })

    void it('should block anonymous users', async () => {
      mock.method(security.authenticatedUsers, 'get', () => undefined)
      req.body.imageUrl = 'http://127.0.0.1:3000/photo.jpg'

      await profileImageUrlUpload()(req, res, next)

      assert.equal(fetchMock.mock.calls.length, 0)
      assert.equal(next.mock.calls.length, 1)
      assert.match(next.mock.calls[0].arguments[0].message, /Blocked illegal activity/)
    })
  })
})
