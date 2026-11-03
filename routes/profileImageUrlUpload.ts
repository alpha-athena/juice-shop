/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns/promises'
import net from 'node:net'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

// fd00:ec2::254 - the IPv6 address of the AWS instance metadata service
const IMDS_IPV6_GROUPS = [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254]

function parseIPv6Groups (address: string): number[] | null {
  const zoneless = address.split('%')[0]
  const halves = zoneless.split('::')
  if (halves.length > 2) return null
  const head = halves[0] === '' ? [] : halves[0].split(':')
  const tail = halves.length === 2 && halves[1] !== '' ? halves[1].split(':') : []
  const last = tail.length > 0 ? tail : head
  const lastPart = last[last.length - 1]
  if (lastPart !== undefined && lastPart.includes('.')) { // embedded IPv4, e.g. ::ffff:169.254.169.254
    if (!net.isIPv4(lastPart)) return null
    const octets = lastPart.split('.').map(Number)
    last.splice(last.length - 1, 1, ((octets[0] << 8) | octets[1]).toString(16), ((octets[2] << 8) | octets[3]).toString(16))
  }
  const missing = 8 - head.length - tail.length
  if (missing < 0 || (halves.length === 1 && missing !== 0)) return null
  const groups = [...head, ...Array(missing).fill('0'), ...tail].map(group => parseInt(group, 16))
  if (groups.some(group => Number.isNaN(group) || group < 0 || group > 0xffff)) return null
  return groups
}

/**
 * True for addresses in the link-local range (IPv4 169.254.0.0/16, IPv6 fe80::/10) and for the
 * IPv6 address of the AWS instance metadata service. Cloud providers (AWS, GCP, Azure, ECS task
 * metadata) hand out instance credentials on these addresses; no profile image ever lives there.
 * The address is checked after DNS resolution, so decimal/hex IP spellings and hostnames that
 * resolve to the metadata service are covered as well.
 */
export function isCloudMetadataAddress (address: string): boolean {
  if (net.isIPv4(address)) {
    return address.startsWith('169.254.')
  }
  if (net.isIPv6(address)) {
    const groups = parseIPv6Groups(address)
    if (groups === null) return false
    const isIPv4Mapped = groups.slice(0, 5).every(group => group === 0) && groups[5] === 0xffff
    if (isIPv4Mapped) {
      return (groups[6] >> 8) === 169 && (groups[6] & 0xff) === 254
    }
    if ((groups[0] & 0xffc0) === 0xfe80) return true
    return groups.every((group, index) => group === IMDS_IPV6_GROUPS[index])
  }
  return false
}

/**
 * Fetches a user-supplied profile image URL. Refuses to contact link-local / cloud metadata
 * addresses and does not follow redirects (a redirect to such an address would otherwise bypass
 * the check). Any other destination, including localhost, is still fetched as before.
 */
export async function fetchProfileImage (url: string): Promise<globalThis.Response> {
  const hostname = new URL(url).hostname.replace(/^\[|\]$/g, '')
  const resolved = await dns.lookup(hostname, { all: true })
  if (resolved.some(({ address }) => isCloudMetadataAddress(address))) {
    throw new Error('url resolves to a link-local or cloud metadata address')
  }
  return await fetch(url, { redirect: 'manual' })
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const response = await fetchProfileImage(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
