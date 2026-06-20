
"""Markov chain utilities for behavioral analysis."""
import numpy as np
from typing import List, Tuple


class Matrix:
    """Transition probability matrix for Markov chains."""

    def __init__(self, states: List[str]):
        self.states = states
        self.state_index = {s: i for i, s in enumerate(states)}
        n = len(states)
        self.matrix = np.zeros((n, n))

    def add_transition(self, from_state: str, to_state: str, count: int = 1):
        """Record a transition between two states."""
        if from_state in self.state_index and to_state in self.state_index:
            i = self.state_index[from_state]
            j = self.state_index[to_state]
            self.matrix[i][j] += count

    def normalize(self):
        """Convert counts to probabilities."""
        row_sums = self.matrix.sum(axis=1, keepdims=True)
        # Avoid division by zero
        row_sums[row_sums == 0] = 1
        self.matrix = self.matrix / row_sums

    def get_probability(self, from_state: str, to_state: str) -> float:
        """Get transition probability."""
        i = self.state_index.get(from_state, -1)
        j = self.state_index.get(to_state, -1)
        if i >= 0 and j >= 0:
            return float(self.matrix[i][j])
        return 0.0

    def predict_next(self, from_state: str) -> str:
        """Predict the most likely next state."""
        i = self.state_index.get(from_state, -1)
        if i < 0:
            return ""
        probs = self.matrix[i]
        return self.states[int(np.argmax(probs))]
