import './globals.css';
import { THEME_INIT_SCRIPT } from '../lib/theme';

export const metadata = {
  title: 'SecVault',
  description: 'Firewall security and management platform',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <head>
        {/* Applies the saved theme to <html> before first paint, avoiding a
            flash of the wrong theme. Reads localStorage directly — cannot be
            an import, must run synchronously in <head>. See lib/theme.js. */}
        <script dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
