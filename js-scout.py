#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
JS-Scout: A tool to find API endpoints, secrets, and other interesting
information in JavaScript files.

Author: Triage Security Labs
Version: 1.0.0
License: MIT
"""

import argparse
import requests
import re
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from rich.console import Console
from rich.panel import Panel
from concurrent.futures import ThreadPoolExecutor

# --- Configuration ---
VERSION = "1.0.0"
REQUEST_HEADERS = {
    'User-Agent': f'JS-Scout/{VERSION} (https://github.com/TriageSecLabs/JS-Scout)'
}
# Suppress insecure request warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
console = Console()

# Regex patterns for finding interesting things
PATTERNS = {
    "API Endpoints": re.compile(r'[\'"](/api/|/v[1-9]/|/internal/|/private/|/graphql|/api)[a-zA-Z0-9_/.-]*[\'"]'),
    "Subdomains/URLs": re.compile(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    "Potential Secrets": re.compile(r'(secret|token|password|key|auth|bearer)[\'"]?\s*[:=]\s*[\'"][a-zA-Z0-9_.-]{8,}[\'"]', re.IGNORECASE)
}

def find_js_files(base_url, session):
    """Finds all unique JavaScript file URLs on a given page."""
    js_files = set()
    try:
        response = session.get(base_url, headers=REQUEST_HEADERS, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        for script_tag in soup.find_all("script", src=True):
            src = script_tag.get('src')
            if src:
                # Resolve relative URLs
                full_url = urljoin(base_url, src)
                js_files.add(full_url)
    except requests.RequestException as e:
        console.print(f"[bold red]Error fetching {base_url}: {e}[/bold red]")
    return list(js_files)

def analyze_js_content(js_url, session):
    """Downloads and analyzes a single JS file for interesting patterns."""
    findings = {category: set() for category in PATTERNS}
    try:
        response = session.get(js_url, headers=REQUEST_HEADERS, timeout=10, verify=False)
        content = response.text
        
        for category, pattern in PATTERNS.items():
            matches = pattern.findall(content)
            for match in matches:
                # Clean up the match
                cleaned_match = match.strip("'\"")
                findings[category].add(cleaned_match)
                
    except requests.RequestException:
        # Silently fail if a single JS file can't be fetched
        return js_url, None
    
    # Return None if no findings to keep output clean
    if any(findings.values()):
        return js_url, findings
    return js_url, None

def main():
    parser = argparse.ArgumentParser(
        description="JS-Scout: A tool for JavaScript file reconnaissance.",
        epilog="Example: python3 js-scout.py -u https://example.com"
    )
    parser.add_argument("-u", "--url", help="A single URL to scan.")
    parser.add_argument("-l", "--list", help="A file containing a list of URLs to scan.")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads.")
    parser.add_argument("-v", "--version", action="version", version=f"JS-Scout v{VERSION}")
    args = parser.parse_args()

    console.print(f"[bold blue]JS-Scout v{VERSION}[/bold blue] by Triage Security Labs", justify="center")
    console.print("-" * 60)

    if not args.url and not args.list:
        console.print("[bold red]Error: You must provide a URL (-u) or a list of URLs (-l).[/bold red]")
        return
        
    targets = []
    if args.url:
        targets.append(args.url)
    if args.list:
        try:
            with open(args.list, 'r') as f:
                targets.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            console.print(f"[bold red]Error: Input file '{args.list}' not found.[/bold red]")
            return

    session = requests.Session()
    all_js_files = set()

    with console.status("[bold green]Discovering JavaScript files...[/bold green]"):
        for target in targets:
            js_files = find_js_files(target, session)
            all_js_files.update(js_files)

    console.print(f"[*] Found {len(all_js_files)} unique JavaScript files to analyze.")
    console.print("-" * 60)

    if not all_js_files:
        console.print("[yellow]No JavaScript files discovered.[/yellow]")
        return

    total_findings = 0
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_url = {executor.submit(analyze_js_content, js_url, session): js_url for js_url in all_js_files}
        
        for future in future_to_url:
            js_url, findings = future.result()
            if findings:
                total_findings += 1
                panel_content = ""
                for category, matches in findings.items():
                    if matches:
                        panel_content += f"[bold yellow]{category}:[/bold yellow]\n"
                        for match in sorted(list(matches)):
                            panel_content += f"  - [cyan]{match}[/cyan]\n"
                
                console.print(Panel(panel_content, title=f"[bold green]Findings in:[/] [dim]{js_url}[/dim]", border_style="blue"))

    console.print("-" * 60)
    console.print(f"Analysis complete. Found interesting data in {total_findings} of {len(all_js_files)} files.")

if __name__ == "__main__":
    main()
