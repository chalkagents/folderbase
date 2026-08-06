import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';
import { appName, gitConfig } from './shared';

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: (
        <span className="fb-wordmark">
          <span className="fb-mark">FB</span>
          <span>{appName}</span>
          <span className="fb-docs-label">BETA DOCS</span>
        </span>
      ),
    },
    githubUrl: `https://github.com/${gitConfig.user}/${gitConfig.repo}`,
    links: [
      { text: 'v0.7.1', url: '/docs/releases/0.7.1' },
      { text: 'Folderbase.ai', url: 'https://folderbase.ai', external: true },
    ],
  };
}
