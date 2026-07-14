from __future__ import annotations

import math
from collections import Counter


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    value = 0.0
    for count in counts.values():
        probability = count / length
        value -= probability * math.log2(probability)
    return round(value, 3)
