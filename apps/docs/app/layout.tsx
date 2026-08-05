import { RootProvider } from 'fumadocs-ui/provider/next';
import './global.css';
import type { Metadata } from 'next';
import { Analytics } from '@vercel/analytics/next';

export const metadata: Metadata = {
  metadataBase: new URL('https://docs.folderbase.ai'),
  title: {
    default: 'Folderbase Beta Docs — The folder database for AI agents',
    template: '%s · Folderbase Docs',
  },
  description:
    'Beta documentation for installing Folderbase, turning ordinary folders into agent-ready databases, and building against the open CLI and compatibility contract.',
  alternates: { canonical: '/' },
  openGraph: {
    type: 'website',
    url: 'https://docs.folderbase.ai',
    siteName: 'Folderbase Docs',
    title: 'Folderbase Beta Docs',
    description: 'Beta documentation for the open folder database for AI agents.',
    images: [{ url: '/og.png', width: 1600, height: 640, alt: 'Folderbase documentation' }],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Folderbase Beta Docs',
    description: 'Beta documentation for the open folder database for AI agents.',
    images: ['/og.png'],
  },
};

export default function Layout({ children }: LayoutProps<'/'>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="flex flex-col min-h-screen">
        <RootProvider>{children}</RootProvider>
        <Analytics />
      </body>
    </html>
  );
}
