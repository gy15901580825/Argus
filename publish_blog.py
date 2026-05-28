"""Publish a blog post to Argus API.

Usage:
    python publish_blog.py <html_file> [--title "..."] [--summary "..."] [--cover <svg_file>]

If --title / --summary are omitted, the script will prompt for them.
Supports JWT Bearer and x-api-token authentication (auto-detected).
"""
import argparse
import base64
import os
import sys

import requests

API_BASE = "https://www.example.com/api/v1"


def _build_headers(token: str) -> dict:
    headers = {"Content-Type": "application/json"}
    if "." in token and len(token) > 100:
        headers["Authorization"] = f"Bearer {token}"
        print("Using JWT Bearer authentication")
    else:
        headers["x-api-token"] = token
        print("Using API token authentication")
    return headers


def main():
    parser = argparse.ArgumentParser(description="Publish a blog post to Argus")
    parser.add_argument("html_file", help="Path to the HTML content file")
    parser.add_argument("--title", help="Blog title")
    parser.add_argument("--summary", help="Blog summary")
    parser.add_argument("--meta-title", help="SEO meta title")
    parser.add_argument("--meta-description", help="SEO meta description")
    parser.add_argument("--cover", help="Path to SVG cover image file")
    parser.add_argument("--draft", action="store_true", help="Publish as draft instead of published")
    parser.add_argument("--token", help="API token (or set ARGUS_TOKEN env var)")
    args = parser.parse_args()

    # Read content
    if not os.path.exists(args.html_file):
        print(f"Error: file not found: {args.html_file}")
        sys.exit(1)

    with open(args.html_file, "r") as f:
        content = f.read()

    # Token
    token = args.token or os.environ.get("ARGUS_TOKEN")
    if not token:
        token = input("Enter your token (JWT Bearer or x-api-token): ").strip()
    headers = _build_headers(token)

    # Title / summary
    title = args.title or input("Blog title: ").strip()
    summary = args.summary or input("Blog summary (optional, Enter to skip): ").strip() or None

    # Cover image
    cover_uri = None
    if args.cover and os.path.exists(args.cover):
        with open(args.cover, "r") as f:
            svg = f.read()
        cover_uri = "data:image/svg+xml;base64," + base64.b64encode(svg.encode()).decode()
        print(f"Cover image loaded: {len(cover_uri)} chars")

    blog_data = {
        "title": title,
        "content": content,
        "content_format": "html",
        "featured": True,
        "status": "draft" if args.draft else "published",
    }
    if summary:
        blog_data["summary"] = summary
    if args.meta_title:
        blog_data["meta_title"] = args.meta_title
    if args.meta_description:
        blog_data["meta_description"] = args.meta_description
    if cover_uri:
        blog_data["cover_image_url"] = cover_uri
        blog_data["og_image_url"] = cover_uri

    print("\nPublishing blog...")
    resp = requests.post(f"{API_BASE}/blogs", headers=headers, json=blog_data)

    if resp.ok:
        result = resp.json()
        print(f"\nBlog published successfully!")
        print(f"  ID: {result.get('id')}")
        print(f"  Slug: {result.get('slug')}")
        print(f"  URL: https://www.example.com/blog/{result.get('slug')}")
    else:
        print(f"\nFailed to publish: {resp.status_code}")
        print(resp.text)
        sys.exit(1)


if __name__ == "__main__":
    main()
