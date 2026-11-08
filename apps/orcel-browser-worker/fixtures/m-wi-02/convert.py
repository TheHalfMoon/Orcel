"""Turns a saved HTML page into the `body` of a fixture: tags, links and text, in the form
extract.test.ts reads. Dropped: everything in DROP, such as scripts, styles, images and forms and
their controls, and comments. That includes visible text such as a search box's label or a button's. So the "no filter" figure
is a little lower than a browser's. Navigation and footers stay, since removing those is what's
being measured. CSS isn't read, so text a browser would hide stays too."""
import json
import sys
from html.parser import HTMLParser

DROP = {"script", "style", "noscript", "svg", "template", "iframe", "head", "form", "button", "select", "input", "textarea", "label", "img", "picture", "source", "link", "meta", "br", "hr", "wbr"}
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}


class Tree(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = {"tag": "body", "children": []}
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
        node = {"tag": tag, "children": []}
        href = dict(attrs).get("href")
        if tag == "a" and href and href.startswith(("http", "/")):
            node["href"] = href
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
            self.stack[-1]["children"].append(text)


def prune(node):
    """Removes elements with no text under them, and flattens wrappers holding one child."""
    if isinstance(node, str):
        return node
    kept = [child for child in (prune(c) for c in node["children"]) if child is not None]
    if not kept:
        return None
    node["children"] = kept
    if node["tag"] in {"div", "span", "section", "article"} and len(kept) == 1 and not isinstance(kept[0], str):
        return kept[0]
    return node


def words(node):
    if isinstance(node, str):
        return node
    return " ".join(words(child) for child in node["children"])


if __name__ == "__main__":
    tree = Tree()
    tree.feed(open(sys.argv[1], encoding="utf-8", errors="replace").read())
    root = prune(tree.root)
    if root is None:
        raise SystemExit("the page has no text")
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    json.dump(root["children"], sys.stdout, ensure_ascii=False, indent=0)
