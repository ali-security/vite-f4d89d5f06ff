import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, beforeAll, describe, expect, test } from 'vitest'
import { normalizePath } from '../../utils'
import { isWindows } from '../../../shared/utils'
import { type ViteDevServer, createServer } from '../index'
import { checkLoadingAccess, isFileLoadingAllowed } from '../middlewares/static'

const root = normalizePath(
  fileURLToPath(new URL('./fixtures/', import.meta.url)),
)

describe('server.fs.deny', () => {
  let server: ViteDevServer

  beforeAll(async () => {
    server = await createServer({
      configFile: false,
      root,
      logLevel: 'silent',
      appType: 'custom',
      optimizeDeps: { noDiscovery: true },
      server: {
        middlewareMode: true,
        ws: false,
        watch: null,
        fs: { strict: true, allow: [root] },
      },
    })
  })

  afterAll(async () => {
    await server.close()
  })

  test('allows a file inside fs.allow', () => {
    const filePath = path.posix.join(root, 'safe.txt')
    expect(isFileLoadingAllowed(server, filePath)).toBe(true)
  })

  test('denies a denied file', () => {
    const envPath = path.posix.join(root, '.env')
    expect(isFileLoadingAllowed(server, envPath)).toBe(false)
    const crtPath = path.posix.join(root, 'dummy.crt')
    expect(isFileLoadingAllowed(server, crtPath)).toBe(false)
  })

  // `fs.readFile('/foo.png/')` tries to load `'/foo.png'` on Windows
  test('denies a denied file when the path ends with /', () => {
    const envPath = path.posix.join(root, '.env') + '/'
    expect(isFileLoadingAllowed(server, envPath)).toBe(false)
    const crtPath = path.posix.join(root, 'dummy.crt') + '/'
    expect(isFileLoadingAllowed(server, crtPath)).toBe(false)
  })

  // a trailing `\` in the request is normalized to `/` before the check
  test('denies a denied file when the path ends with \\', () => {
    const envPath = path.join(root, '.env') + '\\'
    expect(checkLoadingAccess(server, envPath)).not.toBe('allowed')
    const crtPath = path.join(root, 'dummy.crt') + '\\'
    expect(checkLoadingAccess(server, crtPath)).not.toBe('allowed')
  })

  // On NTFS, `.env::$DATA` exposes the default data stream of `.env`
  test('denies a path with NTFS alternate data stream suffix', () => {
    const envAdsPath = path.posix.join(root, '.env::$DATA')
    expect(isFileLoadingAllowed(server, envAdsPath)).toBe(false)
    const crtAdsPath = path.posix.join(root, 'dummy.crt::$DATA')
    expect(isFileLoadingAllowed(server, crtAdsPath)).toBe(false)
    const namedStreamPath = path.posix.join(root, '.env:stream')
    expect(isFileLoadingAllowed(server, namedStreamPath)).toBe(false)
    const safeAdsPath = path.posix.join(root, 'safe.txt::$DATA')
    expect(isFileLoadingAllowed(server, safeAdsPath)).toBe(false)
    const envAdsSlashPath = path.posix.join(root, '.env::$DATA') + '/'
    expect(isFileLoadingAllowed(server, envAdsSlashPath)).toBe(false)
  })

  test('checkLoadingAccess denies an NTFS ADS path', () => {
    const envAdsPath = path.join(root, '.env::$DATA')
    expect(checkLoadingAccess(server, envAdsPath)).not.toBe('allowed')
  })

  // On Windows, `ENV~1` can be the 8.3 short name of `.env`
  test.runIf(isWindows)('denies a path with Windows 8.3 short name', () => {
    const envShortNamePath = path.posix.join(root, 'ENV~1')
    expect(isFileLoadingAllowed(server, envShortNamePath)).toBe(false)
    const crtShortNamePath = path.posix.join(root, 'DUMMY~1.CRT')
    expect(isFileLoadingAllowed(server, crtShortNamePath)).toBe(false)
    const checkPath = path.join(root, 'ENV~1')
    expect(checkLoadingAccess(server, checkPath)).not.toBe('allowed')
  })

  test.skipIf(isWindows)('allows `~` in the path on non-Windows', () => {
    const filePath = path.posix.join(root, 'safe~1.txt')
    expect(isFileLoadingAllowed(server, filePath)).toBe(true)
  })
})
