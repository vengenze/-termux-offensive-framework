import os
import glob
import re

def convert_md_to_html(md_text):
    html_lines = []
    in_table = False
    
    for line in md_text.splitlines():
        line_stripped = line.strip()
        
        # Headers
        if line_stripped.startswith("# "):
            if in_table:
                html_lines.append("</table>")
                in_table = False
            html_lines.append(f"<h1>{line_stripped[2:]}</h1>")
        elif line_stripped.startswith("## "):
            if in_table:
                html_lines.append("</table>")
                in_table = False
            html_lines.append(f"<h2>{line_stripped[3:]}</h2>")
        elif line_stripped.startswith("### "):
            if in_table:
                html_lines.append("</table>")
                in_table = False
            html_lines.append(f"<h3>{line_stripped[4:]}</h3>")
            
        # Blockquotes
        elif line_stripped.startswith("> "):
            if in_table:
                html_lines.append("</table>")
                in_table = False
            content = line_stripped[2:]
            content = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', content)
            html_lines.append(f"<blockquote>{content}</blockquote>")
            
        # Tables
        elif line_stripped.startswith("|"):
            if "---" in line_stripped:
                continue 
            
            cells = [c.strip() for c in line_stripped.split("|")[1:-1]]
            if not in_table:
                html_lines.append("<table>")
                in_table = True
                html_lines.append("<tr>" + "".join(f"<th>{c}</th>" for c in cells) + "</tr>")
            else:
                formatted_cells = []
                for c in cells:
                    c = re.sub(r'`(.*?)`', r'<code>\1</code>', c)
                    formatted_cells.append(c)
                html_lines.append("<tr>" + "".join(f"<td>{c}</td>" for c in formatted_cells) + "</tr>")
        else:
            if in_table:
                html_lines.append("</table>")
                in_table = False
            if line_stripped:
                formatted_line = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', line_stripped)
                formatted_line = re.sub(r'`(.*?)`', r'<code>\1</code>', formatted_line)
                html_lines.append(f"<p>{formatted_line}</p>")
                
    if in_table:
        html_lines.append("</table>")
        
    return "\n".join(html_lines)

def find_summary_file():
    if os.path.exists("summary.md"):
        return os.path.abspath("summary.md")
    
    matches = glob.glob("recon_*/**/summary.md", recursive=True) + glob.glob("**/summary.md", recursive=True)
    if matches:
        matches.sort(key=os.path.getmtime, reverse=True)
        return os.path.abspath(matches[0])
        
    return None

def generate_html_report():
    print("-" * 60)
    print("[*] Generating Professional HTML Executive Dashboard...")
    print("-" * 60)
    
    summary_path = find_summary_file()
    if not summary_path:
        print("[-] 'summary.md' not found anywhere. Run your pipeline or report generator first.")
        return
        
    print(f"[+] Found summary file at: {summary_path}")
    with open(summary_path, "r", encoding="utf-8") as f:
        md_content = f.read()
        
    html_body = convert_md_to_html(md_content)

    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Offensive Security Assessment Report</title>
    <style>
        :root {{
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --text-color: #c9d1d9;
            --accent-red: #f85149;
            --accent-yellow: #d29922;
            --accent-green: #3fb950;
            --accent-blue: #58a6ff;
            --border-color: #30363d;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 20px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 30px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.5);
        }}
        h1, h2, h3 {{
            color: var(--accent-blue);
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 8px;
        }}
        blockquote {{
            background: rgba(88, 166, 255, 0.1);
            border-left: 4px solid var(--accent-blue);
            margin: 15px 0;
            padding: 15px;
            border-radius: 4px;
            color: #8b949e;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
            margin-bottom: 20px;
        }}
        th, td {{
            border: 1px solid var(--border-color);
            padding: 10px 15px;
            text-align: left;
        }}
        th {{
            background-color: #21262d;
            color: var(--text-color);
        }}
        tr:nth-child(even) {{
            background-color: rgba(255,255,255,0.02);
        }}
        code {{
            font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, monospace;
            background-color: rgba(110, 118, 125, 0.15);
            padding: 0.2em 0.4em;
            border-radius: 6px;
            font-size: 85%;
            color: #79c0ff;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            font-size: 0.85rem;
            color: #8b949e;
            border-top: 1px solid var(--border-color);
            padding-top: 15px;
        }}
    </style>
</head>
<body>
    <div class="container">
        {html_body}
        <div class="footer">
            <p>Generated automatically by Termux Offensive Security Framework &bull; Mobile Reconnaissance Unit</p>
        </div>
    </div>
</body>
</html>
"""

    # Save report.html directly in the same directory as summary.md
    summary_dir = os.path.dirname(summary_path)
    output_filename = os.path.join(summary_dir, "report.html")
    
    with open(output_filename, "w", encoding="utf-8") as f:
        f.write(html_template)
        
    print(f"[+] HTML Dashboard successfully compiled: {output_filename}")
    print("-" * 60)
    
    if os.path.exists("/data/data/com.termux/files/usr/bin/termux-open"):
        print("[*] Opening report in mobile browser...")
        os.system(f"termux-open \"{output_filename}\"")

if __name__ == "__main__":
    generate_html_report()
