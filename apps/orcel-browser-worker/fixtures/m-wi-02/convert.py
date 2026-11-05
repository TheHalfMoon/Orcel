"""Turns a saved HTML page into the Spec tree extract.test.ts's snapshot builder takes:
elements with an href at most, and text. Scripts, styles and comments are dropped. Everything
else stays, navigation and footers included, since removing those is what's being measured."""
import json
import sys
from html.parser import HTMLParser

DROP = {"script", "style", "noscript", "svg", "template", "iframe", "head", "form", "button", "select", "input", "textarea", "label", "img", "picture", "source", "link", "meta", "br", "hr", "wbr"}
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}


class Tree(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = {"kind": "el", "tag": "body", "attrs": {}, "style": {}, "children": []}
        self.stack = [self.root]
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if self.skip:
            if tag in DROP and tag not in VOID:
                self.skip += 1
            return
        if tag in DROP:
            if tag not in VOID:
                self.skip = 1
            return
        if tag in VOID or tag in {"html", "body"}:
            return
        node = {"kind": "el", "tag": tag, "attrs": {}, "style": {}, "children": []}
        href = dict(attrs).get("href")
        if tag == "a" and href and href.startswith(("http", "/")):
            node["attrs"]["href"] = href
        self.stack[-1]["children"].append(node)
        self.stack.append(node)

    def handle_endtag(self, tag):
        if self.skip:
            if tag in DROP and tag not in VOID:
                self.skip -= 1
            return
        for at in range(len(self.stack) - 1, 0, -1):
            if self.stack[at]["tag"] == tag:
                del self.stack[at:]
                return

    def handle_data(self, data):
        if self.skip:
            return
        text = " ".join(data.split())
        if text:
            self.stack[-1]["children"].append({"kind": "text", "text": text, "style": {}})


def prune(node):
    """Removes elements with no text under them, and flattens wrappers holding one child."""
    if node["kind"] == "text":
        return node
    kept = [child for child in (prune(c) for c in node["children"]) if child is not None]
    if not kept:
        return None
    node["children"] = kept
    if node["tag"] in {"div", "span", "section", "article"} and len(kept) == 1 and kept[0]["kind"] == "el":
        return kept[0]
    return node


def words(node):
    if node["kind"] == "text":
        return node["text"]
    return " ".join(words(child) for child in node["children"])


if __name__ == "__main__":
    tree = Tree()
    tree.feed(open(sys.argv[1], encoding="utf-8", errors="replace").read())
    root = prune(tree.root)
    if len(sys.argv) > 2:
        json.dump(root["children"], open(sys.argv[2], "w", encoding="utf-8", newline="\n"), ensure_ascii=False, separators=(",", ":"))
    print(words(root))
