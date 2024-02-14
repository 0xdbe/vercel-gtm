import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'
import { headers } from 'next/headers'

import { getScriptNonceFromHeader } from './helper/get-script-nonce-from-header'

const inter = Inter({ subsets: ['latin'] })

export const dynamic = 'force-dynamic'

export const metadata: Metadata = {
  title: 'Create Next App',
  description: 'Generated by create next app',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {

  const contentSecurityPolicy: string | null = headers().get('Content-Security-Policy')
  const nonce = contentSecurityPolicy ? getScriptNonceFromHeader(contentSecurityPolicy) : null
  console.log('nonce:', nonce)

  return (
    <html lang="en">
      <body className={inter.className}>{children}</body>
    </html>
  )
}
