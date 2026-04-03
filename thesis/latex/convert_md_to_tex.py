"""Convert thesis markdown chapters to LaTeX .tex files."""

import re
import sys
import os

def md_to_latex(md_text, chapter_num):
    """Convert markdown text to LaTeX format."""
    lines = md_text.split('\n')
    output = []
    in_code_block = False
    in_table = False
    table_lines = []

    for line in lines:
        # Skip HTML comments
        if '<!--' in line:
            continue
        if '-->' in line:
            continue

        # Code blocks
        if line.strip().startswith('```'):
            if in_code_block:
                output.append('\\end{lstlisting}')
                in_code_block = False
            else:
                lang = line.strip().replace('```', '').strip()
                if lang:
                    output.append(f'\\begin{{lstlisting}}[language={lang}]')
                else:
                    output.append('\\begin{lstlisting}')
                in_code_block = True
            continue

        if in_code_block:
            output.append(line)
            continue

        # Tables
        if '|' in line and line.strip().startswith('|'):
            if '---' in line:
                continue  # Skip separator
            cells = [c.strip() for c in line.split('|')[1:-1]]
            if not in_table:
                in_table = True
                ncols = len(cells)
                col_spec = 'l' * ncols
                # Check if first row is header
                output.append('\\begin{table}[H]')
                output.append('\\centering')
                output.append(f'\\begin{{tabular}}{{{col_spec}}}')
                output.append('\\toprule')
                output.append(' & '.join([f'\\textbf{{{c}}}' for c in cells]) + ' \\\\')
                output.append('\\midrule')
            else:
                output.append(' & '.join(cells) + ' \\\\')
            continue
        elif in_table:
            output.append('\\bottomrule')
            output.append('\\end{tabular}')
            output.append('\\end{table}')
            in_table = False

        # Chapter heading (# CHƯƠNG...)
        if line.startswith('# CHƯƠNG') or line.startswith('# Chương'):
            title = re.sub(r'^#\s*CHƯƠNG\s*\d+[:.]\s*', '', line, flags=re.IGNORECASE)
            title = re.sub(r'^#\s*Chương\s*\d+[:.]\s*', '', title, flags=re.IGNORECASE)
            title = title.strip()
            if title:
                output.append(f'\\chapter{{{title}}}')
            continue

        # Section headings
        if line.startswith('## '):
            title = line[3:].strip()
            # Remove numbering like "1.1 " or "2.3.1 "
            title = re.sub(r'^\d+\.\d+(\.\d+)?\s+', '', title)
            output.append(f'\\section{{{escape_latex(title)}}}')
            continue

        if line.startswith('### '):
            title = line[4:].strip()
            title = re.sub(r'^\d+\.\d+\.\d+\s+', '', title)
            output.append(f'\\subsection{{{escape_latex(title)}}}')
            continue

        if line.startswith('#### '):
            title = line[5:].strip()
            output.append(f'\\subsubsection{{{escape_latex(title)}}}')
            continue

        # Skip reference sections at end of chapters
        if line.startswith('## Tài liệu tham khảo') or line.startswith('---'):
            continue

        # Blockquote
        if line.startswith('> '):
            text = line[2:].strip()
            output.append(f'\\begin{{quote}}\\textit{{{escape_latex(text)}}}\\end{{quote}}')
            continue

        # Bold text
        line = re.sub(r'\*\*(.+?)\*\*', r'\\textbf{\1}', line)

        # Italic text
        line = re.sub(r'\*(.+?)\*', r'\\textit{\1}', line)

        # Inline code
        line = re.sub(r'`(.+?)`', r'\\texttt{\1}', line)

        # References [number]
        line = re.sub(r'\[(\d+)\]', r'[\\ref*{\1}]', line)
        # Actually keep as-is since we use manual references
        line = re.sub(r'\[\\ref\*\{(\d+)\}\]', r'[\1]', line)

        # Bullet points
        if line.strip().startswith('- '):
            text = line.strip()[2:]
            output.append(f'\\item {escape_latex(text)}')
            continue

        # Numbered list
        m = re.match(r'^\s*(\d+)\.\s+(.+)', line)
        if m:
            text = m.group(2)
            output.append(f'\\item {escape_latex(text)}')
            continue

        # Math formulas ($$...$$)
        if line.strip().startswith('$$') and line.strip().endswith('$$'):
            formula = line.strip()[2:-2]
            output.append(f'\\[{formula}\\]')
            continue

        # Regular paragraph
        if line.strip():
            output.append(escape_latex(line))
        else:
            output.append('')

    # Close any open table
    if in_table:
        output.append('\\bottomrule')
        output.append('\\end{tabular}')
        output.append('\\end{table}')

    return '\n'.join(output)


def escape_latex(text):
    """Escape special LaTeX characters (minimal - avoid breaking commands)."""
    # Don't escape if it already contains LaTeX commands
    if '\\' in text:
        return text
    text = text.replace('&', '\\&')
    text = text.replace('%', '\\%')
    text = text.replace('#', '\\#')
    text = text.replace('_', '\\_')
    # Don't escape $ as it might be math
    return text


def process_chapter(input_path, output_path, chapter_num):
    """Process a single chapter file."""
    with open(input_path, 'r', encoding='utf-8') as f:
        md_content = f.read()

    latex_content = md_to_latex(md_content, chapter_num)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(f'% Chapter {chapter_num}\n')
        f.write(f'% Auto-generated from {os.path.basename(input_path)}\n\n')
        f.write(latex_content)

    print(f'Converted: {input_path} -> {output_path}')


if __name__ == '__main__':
    chapters = [
        ('chapter1_introduction.md', 'chapter1.tex', 1),
        ('chapter2_literature_review.md', 'chapter2.tex', 2),
        ('chapter3_methodology.md', 'chapter3.tex', 3),
        ('chapter4_results.md', 'chapter4.tex', 4),
        ('chapter5_discussion.md', 'chapter5.tex', 5),
        ('chapter6_conclusion.md', 'chapter6.tex', 6),
    ]

    thesis_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    latex_dir = os.path.dirname(os.path.abspath(__file__))

    for md_file, tex_file, num in chapters:
        input_path = os.path.join(thesis_dir, md_file)
        output_path = os.path.join(latex_dir, tex_file)
        if os.path.exists(input_path):
            process_chapter(input_path, output_path, num)
        else:
            print(f'WARNING: {input_path} not found')
