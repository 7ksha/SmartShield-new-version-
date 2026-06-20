
"""Trie data structure for efficient prefix matching."""
from typing import Dict, List, Optional


class TrieNode:
    def __init__(self):
        self.children: Dict[str, "TrieNode"] = {}
        self.is_end = False
        self.value = None


class Trie:
    """Prefix tree for fast string lookups."""

    def __init__(self):
        self.root = TrieNode()

    def insert(self, word: str, value=None):
        """Insert a word into the trie."""
        node = self.root
        for char in word:
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
        node.is_end = True
        node.value = value

    def search(self, word: str) -> bool:
        """Check if a word exists in the trie."""
        node = self._find_node(word)
        return node is not None and node.is_end

    def starts_with(self, prefix: str) -> bool:
        """Check if any word starts with the given prefix."""
        return self._find_node(prefix) is not None

    def _find_node(self, word: str) -> Optional[TrieNode]:
        """Traverse the trie following the word's characters."""
        node = self.root
        for char in word:
            if char not in node.children:
                return None
            node = node.children[char]
        return node

    def get_words_with_prefix(self, prefix: str) -> List[str]:
        """Get all words that start with the given prefix."""
        node = self._find_node(prefix)
        if not node:
            return []
        results = []
        self._collect(node, prefix, results)
        return results

    def _collect(self, node: TrieNode, prefix: str, results: List[str]):
        """Recursively collect words from a node."""
        if node.is_end:
            results.append(prefix)
        for char, child in node.children.items():
            self._collect(child, prefix + char, results)
