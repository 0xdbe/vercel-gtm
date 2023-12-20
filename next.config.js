/** @type {import('next').NextConfig} */
const nextConfig = {
    async headers() {
        return getHeaders()
    }
}

const contentSecurityPolicy = {
    'default-src': [`'none'`],
    'frame-ancestors': [`'none'`],
    'font-src': [`'self'`],
    'form-action': [`'none'`],
    'connect-src':  [
        `'none'`,
    ],
    'img-src': [
        `'self'`,
    ],
    'script-src': [
        `'self'`,
    ],
    'style-src': [ `'self'` ]

}

function getHeaders() {
    return [
        {
          source: '/(.*)',
          headers: [
            { key: 'Content-Security-Policy', value: getContentSecurityPolicy(contentSecurityPolicy)},
            { key: 'X-Content-Type-Options', value: 'nosniff'},
            //{ key: 'Permissions-Policy', value: "...",},
            { key: 'Referrer-Policy', value: 'no-referrer'},
            { key: 'X-Frame-Options',value: 'DENY'},
            { key: 'X-XSS-Protection', value: '0'},
          ],
        },
    ];
}

function getContentSecurityPolicy(config) {
    return Object.entries(config)
    .map(([key, value]) => `${key} ${value.join(' ')}`)
    .join('; ')
  }

module.exports = nextConfig
