"use client";

import Link from "next/link";
import { LogoutButton } from "../auth/LogoutButton";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { cn } from "@/lib/utils";
import { Menu, X } from "lucide-react";

export const Header = () => {
  const pathName = usePathname();
  const [isOpen, setIsOpen] = useState(false);

  const navLinks = [
    { href: "/upload", label: "Upload" },
    { href: "/receive", label: "Received" },
    { href: "/profile", label: "Profile" },
  ];

  return (
    <header className="text-white shadow-md mb-2 mt-4">
      <div className="flex justify-between items-center px-4 py-3 md:px-8">
        {/* Logo */}
        <Link href="/" className="text-2xl font-bold">
          Safe Send
        </Link>

        {/* Desktop Nav */}
        <nav className="hidden md:flex items-center space-x-6">
          {navLinks.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className={cn(
                "transition hover:text-slate-300",
                pathName === link.href && "underline underline-offset-4",
              )}
            >
              {link.label}
            </Link>
          ))}
          <LogoutButton>Logout</LogoutButton>
        </nav>

        {/* Mobile Menu Button */}
        <button
          className="md:hidden"
          onClick={() => setIsOpen(!isOpen)}
          aria-label="Toggle Menu"
        >
          {isOpen ? <X size={28} /> : <Menu size={28} />}
        </button>
      </div>

      {/* Mobile Nav */}
      {isOpen && (
        <div className="md:hidden px-4 pb-4 space-y-3">
          {navLinks.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              onClick={() => setIsOpen(false)}
              className={cn(
                "block py-2 transition hover:text-slate-300",
                pathName === link.href && "underline underline-offset-4",
              )}
            >
              {link.label}
            </Link>
          ))}

          <div className="pt-2 border-t border-slate-700">
            <LogoutButton>Logout</LogoutButton>
          </div>
        </div>
      )}
    </header>
  );
};
