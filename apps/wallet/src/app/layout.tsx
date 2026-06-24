import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Bolyra Wallet — Agent Delegation Manager",
  description: "Create, manage, and revoke AI agent permissions. The human control surface for agent delegation.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen">{children}</body>
    </html>
  );
}
