import { ReactNode } from "react";
import { Header } from "@/components/header/Header";

export default function ProtectedLayout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen flex flex-col">
      <Header />

      <main className="flex-1">{children}</main>
    </div>
  );
}
