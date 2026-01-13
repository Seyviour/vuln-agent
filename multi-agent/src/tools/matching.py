"""
Code matching utilities for fuzzy text matching.

Provides intelligent code matching that handles:
- Whitespace differences
- Indentation variations
- Minor formatting differences
"""

import difflib
from typing import Optional, Tuple

from ..utils.constants import DEFAULT_FUZZY_THRESHOLD, MINIMUM_FUZZY_THRESHOLD


def normalize_whitespace(code: str) -> str:
    """
    Normalize whitespace for fuzzy matching while preserving structure.
    
    - Strips trailing whitespace from each line
    - Normalizes line endings to \\n
    - Preserves leading indentation
    
    Args:
        code: The code string to normalize
    
    Returns:
        Normalized code string
    """
    lines = code.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    normalized = [line.rstrip() for line in lines]
    return '\n'.join(normalized)


def find_best_match(
    needle: str,
    haystack: str,
    threshold: float = DEFAULT_FUZZY_THRESHOLD
) -> Optional[Tuple[int, int, float, str]]:
    """
    Find the best matching substring in haystack for needle using fuzzy matching.
    
    Uses sliding window approach with SequenceMatcher for similarity scoring.
    
    Args:
        needle: The code block to search for
        haystack: The full file content to search in
        threshold: Minimum similarity ratio (0.0 to 1.0)
    
    Returns:
        Tuple of (start_idx, end_idx, similarity_ratio, matched_text) or None
        - start_idx: Starting character index in original haystack
        - end_idx: Ending character index in original haystack
        - similarity_ratio: How similar the match is (1.0 = exact)
        - matched_text: The actual matched text from haystack
    """
    needle_normalized = normalize_whitespace(needle)
    haystack_normalized = normalize_whitespace(haystack)
    
    needle_lines = needle_normalized.split('\n')
    haystack_lines = haystack_normalized.split('\n')
    
    # First try exact match on normalized text
    if needle_normalized in haystack_normalized:
        start = haystack.find(needle)
        if start == -1:
            # Try with normalized haystack to get position
            norm_start = haystack_normalized.find(needle_normalized)
            # Map back to original - find the corresponding original text
            original_lines = haystack.split('\n')
            norm_lines_before = haystack_normalized[:norm_start].count('\n')
            # Reconstruct the original substring
            matched_original_lines = original_lines[
                norm_lines_before:norm_lines_before + len(needle_lines)
            ]
            matched_text = '\n'.join(matched_original_lines)
            start = haystack.find(matched_original_lines[0]) if matched_original_lines else -1
            if start != -1:
                return (start, start + len(matched_text), 1.0, matched_text)
        else:
            return (start, start + len(needle), 1.0, needle)
    
    # Sliding window fuzzy match
    best_match = None
    best_ratio = 0.0
    
    window_size = len(needle_lines)
    
    if window_size > len(haystack_lines):
        return None
    
    for i in range(len(haystack_lines) - window_size + 1):
        window = haystack_lines[i:i + window_size]
        window_text = '\n'.join(window)
        
        # Use SequenceMatcher for similarity
        ratio = difflib.SequenceMatcher(
            None, 
            needle_normalized, 
            window_text
        ).ratio()
        
        if ratio > best_ratio and ratio >= threshold:
            best_ratio = ratio
            # Get the original (non-normalized) text for this window
            original_lines = haystack.replace('\r\n', '\n').replace('\r', '\n').split('\n')
            original_window = '\n'.join(original_lines[i:i + window_size])
            
            # Calculate start position in original text
            start_pos = len('\n'.join(original_lines[:i])) + (1 if i > 0 else 0)
            end_pos = start_pos + len(original_window)
            
            best_match = (start_pos, end_pos, ratio, original_window)
    
    return best_match


def find_closest_match(
    needle: str,
    haystack: str,
    min_threshold: float = MINIMUM_FUZZY_THRESHOLD
) -> Optional[Tuple[float, str]]:
    """
    Find the closest matching section, even if below normal threshold.
    
    Used for generating helpful error messages showing what was closest.
    
    Args:
        needle: The code block to search for
        haystack: The full file content
        min_threshold: Minimum threshold to consider (lower than find_best_match)
    
    Returns:
        Tuple of (similarity, matched_text) or None
    """
    result = find_best_match(needle, haystack, threshold=min_threshold)
    if result:
        _, _, similarity, matched_text = result
        return (similarity, matched_text)
    return None


def count_occurrences(needle: str, haystack: str) -> int:
    """
    Count exact occurrences of needle in haystack.
    
    Args:
        needle: String to search for
        haystack: String to search in
    
    Returns:
        Number of occurrences
    """
    return haystack.count(needle)
