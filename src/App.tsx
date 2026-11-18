import { useState } from 'react';
import { BookOpen, Menu, X } from 'lucide-react';
import { MarkdownRenderer } from './components/MarkdownRenderer.tsx';
import { DOC_SECTIONS } from './docsCatalog.ts';

export default function App() {
  const [activeDocId, setActiveDocId] = useState<string>(DOC_SECTIONS[0].id);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const activeIndex = Math.max(
    0,
    DOC_SECTIONS.findIndex((doc) => doc.id === activeDocId),
  );
  const currentDoc = DOC_SECTIONS[activeIndex];
  const prevDoc = activeIndex > 0 ? DOC_SECTIONS[activeIndex - 1] : null;
  const nextDoc = activeIndex < DOC_SECTIONS.length - 1 ? DOC_SECTIONS[activeIndex + 1] : null;

  function selectDoc(id: string) {
    setActiveDocId(id);
    setMobileMenuOpen(false);
    window.scrollTo({ top: 0 });
  }

  return (
    <div className="min-h-screen flex bg-black text-white">
      <aside className="w-64 shrink-0 border-r border-[#292929] bg-black hidden md:flex flex-col">
        <div className="h-12 px-4 border-b border-[#292929] flex items-center gap-2.5">
          <BookOpen className="w-4 h-4 text-white shrink-0" />
          <span className="text-sm font-semibold tracking-tight text-white whitespace-nowrap">
            AAMARVA Gateway
          </span>
        </div>

        <nav className="flex-1 py-2 overflow-y-auto" aria-label="Documentation navigation">
          {DOC_SECTIONS.map((doc) => {
            const isActive = doc.id === currentDoc.id;
            return (
              <button
                key={doc.id}
                type="button"
                onClick={() => selectDoc(doc.id)}
                aria-current={isActive ? 'page' : undefined}
                className={`relative w-full flex items-center justify-between px-4 py-2 text-xs font-medium cursor-pointer whitespace-nowrap text-left ${
                  isActive
                    ? 'bg-[#121212] text-white'
                    : 'text-[#999999] hover:bg-[#0a0a0a] hover:text-white'
                }`}
              >
                {isActive && (
                  <span
                    aria-hidden="true"
                    className="absolute left-0 top-1.5 bottom-1.5 w-[2px] bg-white"
                  />
                )}
                <span className="truncate">{doc.title}</span>
              </button>
            );
          })}
        </nav>
      </aside>

      {mobileMenuOpen && (
        <div className="fixed inset-0 z-40 flex md:hidden">
          <div
            className="fixed inset-0 bg-black/80"
            onClick={() => setMobileMenuOpen(false)}
            aria-hidden="true"
          />
          <aside className="relative z-50 w-64 max-w-[80vw] bg-black border-r border-[#292929] flex flex-col">
            <div className="h-12 px-4 border-b border-[#292929] flex items-center justify-between">
              <div className="flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-white shrink-0" />
                <span className="text-sm font-semibold text-white whitespace-nowrap">
                  AAMARVA Gateway
                </span>
              </div>
              <button
                type="button"
                onClick={() => setMobileMenuOpen(false)}
                aria-label="Close navigation"
                className="p-1.5 text-white border border-[#292929] bg-black hover:border-white cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <nav className="flex-1 py-2 overflow-y-auto" aria-label="Mobile documentation navigation">
              {DOC_SECTIONS.map((doc) => {
                const isActive = doc.id === currentDoc.id;
                return (
                  <button
                    key={doc.id}
                    type="button"
                    onClick={() => selectDoc(doc.id)}
                    aria-current={isActive ? 'page' : undefined}
                    className={`relative w-full flex items-center px-4 py-2.5 text-xs font-medium cursor-pointer whitespace-nowrap text-left ${
                      isActive
                        ? 'bg-[#121212] text-white'
                        : 'text-[#999999] hover:bg-[#0a0a0a] hover:text-white'
                    }`}
                  >
                    {isActive && (
                      <span
                        aria-hidden="true"
                        className="absolute left-0 top-2 bottom-2 w-[2px] bg-white"
                      />
                    )}
                    <span className="truncate">{doc.title}</span>
                  </button>
                );
              })}
            </nav>
          </aside>
        </div>
      )}

      <div className="flex-1 flex flex-col min-w-0 bg-black">
        <header className="h-12 px-4 md:px-8 border-b border-[#292929] bg-black flex items-center justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setMobileMenuOpen(true)}
              aria-label="Open navigation"
              aria-expanded={mobileMenuOpen}
              className="md:hidden p-1.5 text-white bg-black border border-[#292929] hover:border-white cursor-pointer shrink-0"
            >
              <Menu className="w-4 h-4" />
            </button>

            <div className="flex items-center gap-2 text-xs text-[#999999] truncate">
              <span className="font-medium text-white truncate">Documentation</span>
              <span aria-hidden="true">/</span>
              <span className="truncate">{currentDoc.title}</span>
            </div>
          </div>

          <span className="font-mono text-[11px] text-[#999999] whitespace-nowrap shrink-0">
            {currentDoc.path}
          </span>
        </header>

        <main className="flex-1 w-full max-w-4xl mx-auto px-4 md:px-8 py-8 bg-black">
          <MarkdownRenderer content={currentDoc.content} />

          <div className="mt-10 pt-5 border-t border-[#292929] flex items-center justify-between gap-4">
            {prevDoc ? (
              <button
                type="button"
                onClick={() => selectDoc(prevDoc.id)}
                className="px-3.5 py-2 text-xs text-white bg-black border border-[#292929] hover:border-white cursor-pointer text-left"
              >
                <span className="block text-[11px] text-[#999999]">Previous</span>
                <span className="font-medium">{prevDoc.title}</span>
              </button>
            ) : (
              <div />
            )}

            {nextDoc ? (
              <button
                type="button"
                onClick={() => selectDoc(nextDoc.id)}
                className="px-3.5 py-2 text-xs text-white bg-black border border-[#292929] hover:border-white cursor-pointer text-right"
              >
                <span className="block text-[11px] text-[#999999]">Next</span>
                <span className="font-medium">{nextDoc.title}</span>
              </button>
            ) : (
              <div />
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
