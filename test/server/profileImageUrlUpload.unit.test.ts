/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { describe, it, beforeEach, afterEach, mock } from 'node:test'
import assert from 'node:assert/strict'
import { isCloudMetadataAddress, fetchProfileImage } from '../../routes/profileImageUrlUpload'

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

  void describe('fetchProfileImage', () => {
    const originalFetch = globalThis.fetch
    let fetchMock: any

    beforeEach(() => {
      fetchMock = mock.fn(async () => new Response('ok', { status: 200 }))
      globalThis.fetch = fetchMock
    })

    afterEach(() => {
      globalThis.fetch = originalFetch
    })

    void it('should refuse to fetch the AWS instance metadata service', async () => {
      await assert.rejects(fetchProfileImage('http://169.254.169.254/latest/meta-data/iam/security-credentials/'), /metadata/)
      assert.equal(fetchMock.mock.calls.length, 0)
    })

    void it('should refuse to fetch the ECS task metadata endpoint', async () => {
      await assert.rejects(fetchProfileImage('http://169.254.170.2/v2/credentials/'), /metadata/)
      assert.equal(fetchMock.mock.calls.length, 0)
    })

    void it('should refuse to fetch the AWS instance metadata service via IPv6', async () => {
      await assert.rejects(fetchProfileImage('http://[fd00:ec2::254]/latest/meta-data/'), /metadata/)
      assert.equal(fetchMock.mock.calls.length, 0)
    })

    void it('should refuse to fetch the metadata service spelled as a decimal integer', async () => {
      // 2852039166 === 169.254.169.254; the URL parser or the resolver normalises the numeric form
      await assert.rejects(fetchProfileImage('http://2852039166/latest/meta-data/'))
      assert.equal(fetchMock.mock.calls.length, 0)
    })

    void it('should still fetch localhost so the "ssrfChallenge" keeps working', async () => {
      await fetchProfileImage('http://localhost:3000/solve/challenges/server-side?key=test')
      assert.equal(fetchMock.mock.calls.length, 1)
      assert.equal(fetchMock.mock.calls[0].arguments[0], 'http://localhost:3000/solve/challenges/server-side?key=test')
    })

    void it('should still fetch loopback IP addresses', async () => {
      await fetchProfileImage('http://127.0.0.1:3000/photo.jpg')
      assert.equal(fetchMock.mock.calls.length, 1)
    })

    void it('should not follow redirects, so a redirect cannot reach the metadata service', async () => {
      await fetchProfileImage('http://127.0.0.1:3000/photo.jpg')
      assert.equal(fetchMock.mock.calls[0].arguments[1].redirect, 'manual')
    })

    void it('should reject URLs without a scheme like fetch() did before', async () => {
      await assert.rejects(fetchProfileImage('cataas.com/cat'))
      assert.equal(fetchMock.mock.calls.length, 0)
    })
  })
})
