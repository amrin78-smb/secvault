import './globals.css';

export const metadata = {
  title: 'SecVault',
  description: 'Firewall security and management platform',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" data-theme="dark">
      <body className="bg-bg-base text-text-primary min-h-screen">{children}</body>
    </html>
  );
}
