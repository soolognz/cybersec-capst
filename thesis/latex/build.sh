#!/bin/bash
# Build thesis PDF from markdown chapters using pandoc + xelatex
cd "$(dirname "$0")/.."

echo "=== Building thesis PDF ==="

# Combine all chapters with front matter
cat > latex/combined_thesis.md << 'FRONTMATTER'
---
title: |
  ỨNG DỤNG AI TRONG PHÁT HIỆN VÀ PHÒNG CHỐNG TẤN CÔNG BRUTE-FORCE TRÊN HỆ THỐNG SSH VỚI DỰ ĐOÁN SỚM
subtitle: |
  Application of AI in Detecting and Preventing Brute-Force Attacks on SSH Systems with Early Prediction
author: |
  KHÓA LUẬN TỐT NGHIỆP — Trường Đại học FPT — An toàn thông tin
date: "Hà Nội, 2026"
---

FRONTMATTER

# Append all chapters
for ch in chapter1_introduction.md chapter2_literature_review.md chapter3_methodology.md chapter4_results.md chapter5_discussion.md chapter6_conclusion.md; do
    echo "" >> latex/combined_thesis.md
    cat "$ch" >> latex/combined_thesis.md
    echo "" >> latex/combined_thesis.md
done

echo "Combined markdown created."

# Build PDF with pandoc
pandoc latex/combined_thesis.md \
    --pdf-engine=xelatex \
    -V documentclass=report \
    -V classoption=a4paper \
    -V geometry:"top=3.5cm,bottom=3cm,left=3.5cm,right=2cm" \
    -V fontsize=13pt \
    -V linestretch=1.5 \
    -V indent=true \
    --toc --toc-depth=3 \
    --number-sections \
    -V header-includes:"\usepackage{indentfirst}\usepackage{float}\usepackage{booktabs}" \
    -o latex/thesis_report.pdf \
    2>&1

echo "=== Build complete ==="
ls -la latex/thesis_report.pdf
