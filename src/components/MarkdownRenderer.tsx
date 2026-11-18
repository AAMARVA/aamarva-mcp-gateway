import type { ReactNode } from 'react';

interface MarkdownRendererProps {
  content: string;
}

type Block =
  | { type: 'heading'; level: 1 | 2 | 3; text: string }
  | { type: 'paragraph'; text: string }
  | { type: 'code'; language: string; code: string }
  | { type: 'hr' }
  | { type: 'table'; headers: string[]; rows: string[][] }
  | { type: 'list'; ordered: boolean; items: ListItem[] };

interface ListItem {
  text: string;
  children: string[];
}

function renderInline(text: string): ReactNode[] {
  const tokens: ReactNode[] = [];
  const pattern = /(`[^`]+`|\*\*[^*]+\*\*)/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  let keyIdx = 0;

  while ((match = pattern.exec(text)) !== null) {
    if (match.index > lastIndex) {
      tokens.push(text.slice(lastIndex, match.index));
    }

    const token = match[0];
    if (token.startsWith('`') && token.endsWith('`')) {
      tokens.push(
        <code
          key={`code-${keyIdx++}`}
          className="font-mono text-[12px] text-white bg-[#0d0d0d] border border-[#292929] px-1.5 py-0.5"
        >
          {token.slice(1, -1)}
        </code>,
      );
    } else if (token.startsWith('**') && token.endsWith('**')) {
      tokens.push(
        <strong key={`bold-${keyIdx++}`} className="font-semibold text-white">
          {renderInline(token.slice(2, -2))}
        </strong>,
      );
    }

    lastIndex = pattern.lastIndex;
  }

  if (lastIndex < text.length) {
    tokens.push(text.slice(lastIndex));
  }

  return tokens;
}

function splitTableRow(line: string): string[] {
  const trimmed = line.trim();
  const stripped = trimmed.replace(/^\|/, '').replace(/\|$/, '');
  return stripped.split('|').map((cell) => cell.trim());
}

function isTableSeparator(line: string): boolean {
  const trimmed = line.trim();
  return /^\|?(\s*:?-{3,}:?\s*\|)+\s*:?-{3,}:?\s*\|?$/.test(trimmed);
}

function parseBlocks(markdown: string): Block[] {
  const lines = markdown.replace(/\r\n/g, '\n').split('\n');
  const blocks: Block[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const trimmed = line.trim();

    if (trimmed === '') {
      i++;
      continue;
    }

    if (trimmed.startsWith('```')) {
      const language = trimmed.slice(3).trim();
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith('```')) {
        codeLines.push(lines[i]);
        i++;
      }
      if (i < lines.length) i++;
      blocks.push({ type: 'code', language, code: codeLines.join('\n') });
      continue;
    }

    if (/^-{3,}$/.test(trimmed)) {
      blocks.push({ type: 'hr' });
      i++;
      continue;
    }

    const headingMatch = /^(#{1,3})\s+(.+)$/.exec(trimmed);
    if (headingMatch) {
      blocks.push({
        type: 'heading',
        level: headingMatch[1].length as 1 | 2 | 3,
        text: headingMatch[2].trim(),
      });
      i++;
      continue;
    }

    if (trimmed.includes('|') && i + 1 < lines.length && isTableSeparator(lines[i + 1])) {
      const headers = splitTableRow(trimmed);
      i += 2;
      const rows: string[][] = [];
      while (i < lines.length) {
        const rowLine = lines[i].trim();
        if (rowLine === '' || !rowLine.includes('|')) break;
        rows.push(splitTableRow(rowLine));
        i++;
      }
      blocks.push({ type: 'table', headers, rows });
      continue;
    }

    const orderedMatch = /^\d+\.\s+(.+)$/.exec(trimmed);
    const unorderedMatch = /^[-*]\s+(.+)$/.exec(trimmed);
    if (orderedMatch || unorderedMatch) {
      const ordered = Boolean(orderedMatch);
      const items: ListItem[] = [];

      while (i < lines.length) {
        const current = lines[i];
        const currentTrimmed = current.trim();
        if (currentTrimmed === '') break;

        const topOrdered = /^\d+\.\s+(.+)$/.exec(current);
        const topUnordered = /^[-*]\s+(.+)$/.exec(current);

        if (ordered && topOrdered) {
          items.push({ text: topOrdered[1], children: [] });
          i++;
          continue;
        }
        if (!ordered && topUnordered) {
          items.push({ text: topUnordered[1], children: [] });
          i++;
          continue;
        }

        const nestedBullet = /^\s{2,}[-*]\s+(.+)$/.exec(current);
        if (nestedBullet && items.length > 0) {
          items[items.length - 1].children.push(nestedBullet[1]);
          i++;
          continue;
        }

        break;
      }

      blocks.push({ type: 'list', ordered, items });
      continue;
    }

    const paragraphLines: string[] = [];
    while (i < lines.length) {
      const current = lines[i];
      const currentTrimmed = current.trim();
      if (
        currentTrimmed === '' ||
        currentTrimmed.startsWith('```') ||
        /^#{1,3}\s+/.test(currentTrimmed) ||
        /^-{3,}$/.test(currentTrimmed) ||
        /^\d+\.\s+/.test(currentTrimmed) ||
        /^[-*]\s+/.test(currentTrimmed) ||
        (currentTrimmed.includes('|') && i + 1 < lines.length && isTableSeparator(lines[i + 1]))
      ) {
        break;
      }
      paragraphLines.push(currentTrimmed);
      i++;
    }
    if (paragraphLines.length > 0) {
      blocks.push({ type: 'paragraph', text: paragraphLines.join(' ') });
    }
  }

  return blocks;
}

export function MarkdownRenderer({ content }: MarkdownRendererProps) {
  const blocks = parseBlocks(content);

  return (
    <article className="space-y-5 text-sm leading-relaxed text-[#cccccc]">
      {blocks.map((block, index) => {
        if (block.type === 'heading') {
          if (block.level === 1) {
            return (
              <h1
                key={index}
                className="text-xl font-semibold tracking-tight text-white pb-3 border-b border-[#292929]"
              >
                {renderInline(block.text)}
              </h1>
            );
          }
          if (block.level === 2) {
            return (
              <h2
                key={index}
                className="text-base font-semibold tracking-tight text-white pt-3 pb-1.5 border-b border-[#292929]"
              >
                {renderInline(block.text)}
              </h2>
            );
          }
          return (
            <h3 key={index} className="text-sm font-semibold text-white pt-2">
              {renderInline(block.text)}
            </h3>
          );
        }

        if (block.type === 'paragraph') {
          return (
            <p key={index} className="text-[13px] leading-6 text-[#cccccc]">
              {renderInline(block.text)}
            </p>
          );
        }

        if (block.type === 'hr') {
          return <hr key={index} className="border-0 border-t border-[#292929] my-4" />;
        }

        if (block.type === 'code') {
          return (
            <div key={index} className="border border-[#292929] bg-black">
              {block.language && (
                <div className="px-3 py-1.5 border-b border-[#292929] text-[11px] font-mono text-[#999999]">
                  {block.language}
                </div>
              )}
              <pre className="p-3.5 text-xs font-mono text-white overflow-x-auto leading-relaxed">
                <code>{block.code}</code>
              </pre>
            </div>
          );
        }

        if (block.type === 'table') {
          return (
            <div key={index} className="border border-[#292929] bg-black overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-[#292929] bg-[#0a0a0a] text-[#999999]">
                    {block.headers.map((header, hIdx) => (
                      <th key={hIdx} className="py-2 px-3 font-medium whitespace-nowrap">
                        {renderInline(header)}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#292929]">
                  {block.rows.map((row, rIdx) => (
                    <tr key={rIdx} className="hover:bg-[#0a0a0a]">
                      {row.map((cell, cIdx) => (
                        <td
                          key={cIdx}
                          className={`py-2 px-3 align-top ${
                            cIdx === 0 ? 'text-white font-medium' : 'text-[#999999]'
                          }`}
                        >
                          {renderInline(cell)}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          );
        }

        if (block.type === 'list') {
          const ListTag = block.ordered ? 'ol' : 'ul';
          return (
            <ListTag
              key={index}
              className={`space-y-2 text-[13px] leading-6 text-[#cccccc] pl-5 ${
                block.ordered ? 'list-decimal' : 'list-disc'
              } marker:text-[#999999]`}
            >
              {block.items.map((item, itemIdx) => (
                <li key={itemIdx}>
                  <span>{renderInline(item.text)}</span>
                  {item.children.length > 0 && (
                    <ul className="mt-1.5 space-y-1 pl-5 list-disc marker:text-[#999999]">
                      {item.children.map((child, cIdx) => (
                        <li key={cIdx}>{renderInline(child)}</li>
                      ))}
                    </ul>
                  )}
                </li>
              ))}
            </ListTag>
          );
        }

        return null;
      })}
    </article>
  );
}
