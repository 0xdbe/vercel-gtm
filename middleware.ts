import { NextRequest, NextResponse } from 'next/server'
 
export function middleware(request: NextRequest) {

  // step 1
  const response = initResponse()

  // step 2
  const reportUri = getReportUri()
  response.headers.set(
    'Report-To', getReportToHeaderValue(reportUri)
  )

  // step 3
  const nonce = getNonce()
  response.headers.set(
    'Content-Security-Policy',
    getContentSecurityPolicyHeaderValue(nonce, reportUri)
  )

  return response
}

function initResponse(): NextResponse {
  return NextResponse.next()
}

function getNonce(): string {
  return Buffer.from(crypto.randomUUID()).toString('base64')
}

function getReportUri(): string {
  return 'https://o4504813195624448.ingest.sentry.io/api/4504813205848064/security/?sentry_key=a67c95b1e54f4a51bb55765b27ca647a'
}

const getReportToHeaderValue = (reportUri: string): string => {
  const reportTo = {
    group: 'csp',
    max_age: 10886400, //1 day
    endpoints: [{ url: reportUri }],
  }
  return JSON.stringify(reportTo)
}

function getContentSecurityPolicyHeaderValue(
    nonce: string,
    reportUri: string,
  ): string {
    const contentSecurityPolicyDirective = {
      'base-uri': [`'self'`],
      'default-src': [`'none'`],
      'frame-ancestors': [`'none'`],
      'font-src': [`'self'`],
      'form-action': [`'self'`],
      'frame-src': [`'self'`],
      'connect-src': [`'self'`],
      'img-src': [`'self'`],
      'manifest-src': [`'self'`],
      'object-src': [`'none'`],
      'report-uri': [reportUri], // for old browsers like Firefox
      'report-to': ['csp'], // for modern browsers like Chrome
      'script-src': [
        `'nonce-${nonce}'`,
        `'strict-dynamic'`, // force hashes and nonces over domain host lists
      ],
      'style-src': [`'self'`],
    }
  
    if (process.env.NODE_ENV === 'development') {
      // Webpack use eval() in development mode for automatic JS reloading
      contentSecurityPolicyDirective['script-src'].push(`'unsafe-eval'`)
    }
  
    if (process.env.NEXT_PUBLIC_VERCEL_ENV === 'preview') {
      contentSecurityPolicyDirective['connect-src'].push('https://vercel.live')
      contentSecurityPolicyDirective['connect-src'].push('wss://*.pusher.com')
      contentSecurityPolicyDirective['img-src'].push('https://vercel.com')
      contentSecurityPolicyDirective['font-src'].push('https://vercel.live')
      contentSecurityPolicyDirective['frame-src'].push('https://vercel.live')
      contentSecurityPolicyDirective['style-src'].push('https://vercel.live')
    }

    // For Sentry (CSP Report Violation)
    contentSecurityPolicyDirective['connect-src'].push('sentry.io')

    // For Google Tag Manager (Debug and Preview Mode)
    contentSecurityPolicyDirective['font-src'].push(`https://fonts.gstatic.com/`)
    contentSecurityPolicyDirective['img-src'].push(`https://www.googletagmanager.com`)
    contentSecurityPolicyDirective['img-src'].push(`https://fonts.gstatic.com`)
    contentSecurityPolicyDirective['img-src'].push(`data:`)
    contentSecurityPolicyDirective['script-src'].push(`'unsafe-eval'`)
    contentSecurityPolicyDirective['style-src'].push(`https://www.googletagmanager.com`)
    contentSecurityPolicyDirective['style-src'].push(`https://fonts.googleapis.com`)
    contentSecurityPolicyDirective['style-src'].push(`'unsafe-inline'`)
  
    return Object.entries(contentSecurityPolicyDirective)
      .map(([key, value]) => `${key} ${value.join(' ')}`)
      .join('; ')

}
