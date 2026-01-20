"""
Copyright 2025 NW-Diff Contributors
SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

This file was created or modified with the assistance of an AI (Large Language Model).
Review required for correctness, security, and licensing.
"""

import html as html_lib

from diff_match_patch import diff_match_patch


def compute_diff_status(origin_data, dest_data):
    """
    Uses diff_match_patch to compute the diff between origin and dest data,
    and returns "identical" if there are no differences, otherwise "changes detected".
    """
    dmp = diff_match_patch()
    diffs = dmp.diff_main(origin_data, dest_data)
    dmp.diff_cleanupSemantic(diffs)
    if len(diffs) == 1 and diffs[0][0] == 0:
        return "identical"
    return "changes detected"


def compute_diff(origin_data, dest_data, view="inline"):
    """
    Computes diff information using diff_match_patch.
    For inline view:
      - If a line contains any diff tags, the entire line is
        highlighted with a yellow background.
      - Additionally, text within <del> tags gets a red background
        and text within <ins> tags gets a blue background.
    """
    dmp = diff_match_patch()
    diffs = dmp.diff_main(origin_data, dest_data)
    dmp.diff_cleanupSemantic(diffs)

    if all(op == 0 for op, text in diffs):
        status = "identical"
        if view == "sidebyside":
            diff_html = generate_side_by_side_html(origin_data, dest_data)
        else:
            # Escape HTML to prevent XSS
            diff_html = f"<pre>{html_lib.escape(origin_data)}</pre>"
    else:
        status = "changes detected"
        if view == "sidebyside":
            diff_html = generate_side_by_side_html(origin_data, dest_data)
        else:
            # Note: diff_prettyHtml automatically escapes HTML entities in the text
            # This has been verified - it converts < to &lt;, > to &gt;, etc.
            raw_diff_html = dmp.diff_prettyHtml(diffs)
            # Replace ¶ and &para; with line breaks
            inline_html = raw_diff_html.replace("¶", "<br>").replace("&para;", "")

            # Update at character level: add inline background color for diff tags
            inline_html = inline_html.replace(
                "<del>", '<del style="background-color: #ffcccc;">'
            )
            inline_html = inline_html.replace(
                "<ins>", '<ins style="background-color: #cce5ff;">'
            )

            # Highlight entire lines that contain diff tags with a yellow background
            lines = inline_html.split("<br>")
            new_lines = []
            for line in lines:
                if "<del" in line or "<ins" in line:
                    new_lines.append(
                        f'<div style="background-color: #ffff99;">{line}</div>'
                    )
                else:
                    new_lines.append(line)
            diff_html = "<br>".join(new_lines)
    return status, diff_html


def generate_side_by_side_html(origin_data, dest_data):
    """
    Generates side-by-side HTML displaying the origin content
    (common parts plus deletions) on the left and the destination
    content (common parts plus insertions) on the right.
    For each column:
      - At the character level, text in <del> tags is highlighted
        with a red background and text in <ins> tags with a blue
        background.
      - At the line level, any line containing diff tags is wrapped
        with a yellow background.
    All text is HTML-escaped to prevent XSS attacks.
    """
    dmp = diff_match_patch()
    diffs = dmp.diff_main(origin_data, dest_data)
    dmp.diff_cleanupSemantic(diffs)

    origin_parts = []
    dest_parts = []
    for op, text in diffs:
        # Escape text to prevent XSS
        escaped_text = html_lib.escape(text)
        if op == 0:
            origin_parts.append(escaped_text)
            dest_parts.append(escaped_text)
        elif op == -1:
            # Highlight deleted text with a red background
            origin_parts.append(
                f"<del style='background-color: #ffcccc;'>{escaped_text}</del>"
            )
        elif op == 1:
            # Highlight added text with a blue background
            dest_parts.append(
                f"<ins style='background-color: #cce5ff;'>{escaped_text}</ins>"
            )
    origin_html = "".join(origin_parts)
    dest_html = "".join(dest_parts)

    # Replace newlines with <br> to preserve formatting
    origin_html = origin_html.replace("\n", "<br>")
    dest_html = dest_html.replace("\n", "<br>")

    # Origin side: wrap lines containing diff tags with a yellow background
    new_origin_lines = []
    for line in origin_html.split("<br>"):
        if "<del" in line or "<ins" in line:
            new_origin_lines.append(
                f"<div style='background-color: #ffff99;'>{line}</div>"
            )
        else:
            new_origin_lines.append(line)
    origin_html = "<br>".join(new_origin_lines)

    # Destination side: wrap lines containing diff tags with a yellow background
    new_dest_lines = []
    for line in dest_html.split("<br>"):
        if "<del" in line or "<ins" in line:
            new_dest_lines.append(
                f"<div style='background-color: #ffff99;'>{line}</div>"
            )
        else:
            new_dest_lines.append(line)
    dest_html = "<br>".join(new_dest_lines)

    # Build the side-by-side table HTML
    table_class = "table table-bordered"
    table_style = "width:100%; border-collapse: collapse; table-layout: fixed;"
    td_style = (
        "vertical-align: top; width:50%; white-space: pre-wrap; "
        "word-break: break-word; overflow-wrap: break-word;"
    )
    html = f"""<table class="{table_class}" style="{table_style}">
  <tr>
    <td style="{td_style}">{origin_html}</td>
    <td style="{td_style}">{dest_html}</td>
  </tr>
</table>"""
    return html
