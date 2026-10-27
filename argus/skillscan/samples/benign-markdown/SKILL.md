---
name: markdown-tidy
description: Tidies markdown files - consistent headings, list markers, blank lines and table alignment - without changing the text.
---

# Markdown Tidy

Cleans up the formatting of markdown files so diffs stay small and the files
render the same everywhere. It never rewrites the prose.

## Rules

1. Use ATX headings (`#`, `##`) with one space after the hashes.
2. Put one blank line before and after every heading, list and code block.
3. Use `-` for unordered lists and `1.` for every item of an ordered list.
4. Give fenced code blocks a language tag when the language is obvious.
5. Align table pipes and give every table a header separator row.
6. Remove trailing whitespace and end the file with a single newline.

## How to apply

Read each `.md` file the user names (or every `.md` file in the current
directory if they name none), apply the rules above with the Edit tool, and
then list the files you changed. Leave files that already follow the rules
untouched.
