import type { MetadataRoute } from 'next';
import { source } from '@/lib/source';

export default function sitemap(): MetadataRoute.Sitemap {
  const now = new Date('2026-08-02T06:38:04Z');
  return [
    { url: 'https://docs.folderbase.ai', lastModified: now, priority: 1 },
    ...source.getPages().map((page) => ({
      url: `https://docs.folderbase.ai${page.url}`,
      lastModified: now,
      priority: page.url === '/docs' ? 0.9 : 0.7,
    })),
  ];
}
