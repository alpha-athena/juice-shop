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

// Cloud providers hand out instance credentials on link-local addresses (AWS/GCP/Azure IMDS at
// 169.254.169.254, ECS task metadata at 169.254.170.2, AWS IMDS over IPv6 at fd00:ec2::254).
// No profile image lives there. BlockList also matches IPv4-mapped IPv6 forms (::ffff:169.254.x.x).
const cloudMetadataAddresses = new net.BlockList()
cloudMetadataAddresses.addSubnet('169.254.0.0', 16, 'ipv4')
cloudMetadataAddresses.addSubnet('fe80::', 10, 'ipv6')
cloudMetadataAddresses.addAddress('fd00:ec2::254', 'ipv6')

export function isCloudMetadataAddress (address: string): boolean {
  if (net.isIPv4(address)) return cloudMetadataAddresses.check(address, 'ipv4')
  if (net.isIPv6(address)) return cloudMetadataAddresses.check(address, 'ipv6')
  return false
}

async function fetchProfileImage (url: string) {
  const hostname = new URL(url).hostname.replace(/^\[|\]$/g, '')
  const addresses = await dns.lookup(hostname, { all: true }) // same resolver fetch() connects through
  if (addresses.some(({ address }) => isCloudMetadataAddress(address))) {
    throw new Error('url resolves to a link-local or cloud metadata address')
  }
  return await fetch(url, { redirect: 'manual' }) // a redirect to such an address would bypass the check above
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
