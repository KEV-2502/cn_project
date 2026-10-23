"""Streaming Data Loader and Quality Auditor for CIC-IDS2017 Archive.

Reads CSV files directly from data/datasets/GeneratedLabelledFlows.zip without extracting
the full archive to disk. Handles header whitespace, duplicate column names, Windows-1252
label encoding (e.g. en-dash in Web Attacks), trailing empty comma rows, and non-finite values.
"""

import csv
import io
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple, Any

# Canonical label normalization mapping
LABEL_NORMALIZATION = {
    "BENIGN": "BENIGN",
    "FTP-Patator": "FTP-Patator",
    "SSH-Patator": "SSH-Patator",
    "DoS Hulk": "DoS Hulk",
    "DoS GoldenEye": "DoS GoldenEye",
    "DoS slowloris": "DoS slowloris",
    "DoS Slowhttptest": "DoS Slowhttptest",
    "Heartbleed": "Heartbleed",
    "Web Attack – Brute Force": "Web Attack - Brute Force",
    "Web Attack \x96 Brute Force": "Web Attack - Brute Force",
    "Web Attack – XSS": "Web Attack - XSS",
    "Web Attack \x96 XSS": "Web Attack - XSS",
    "Web Attack – Sql Injection": "Web Attack - SQL Injection",
    "Web Attack \x96 Sql Injection": "Web Attack - SQL Injection",
    "Infiltration": "Infiltration",
    "Bot": "Bot",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
}


@dataclass
class FileAuditStats:
    filename: str
    total_raw_lines: int = 0
    header_columns_count: int = 0
    empty_lines_dropped: int = 0
    malformed_rows_dropped: int = 0
    exact_duplicates_count: int = 0
    nan_inf_rows_count: int = 0
    negative_duration_count: int = 0
    zero_duration_count: int = 0
    valid_records_yielded: int = 0
    label_counts: Dict[str, int] = field(default_factory=dict)
    exclusion_reasons: Dict[str, int] = field(default_factory=dict)


def clean_header(raw_headers: List[str]) -> List[str]:
    """Clean header names by stripping whitespace and disambiguating duplicates."""
    cleaned = []
    seen = {}
    for h in raw_headers:
        name = h.strip()
        if name in seen:
            seen[name] += 1
            cleaned.append(f"{name}_{seen[name]}")
        else:
            seen[name] = 1
            cleaned.append(name)
    return cleaned


def normalize_label(raw_label: str) -> Optional[str]:
    """Clean and normalize label string; return None if empty or invalid."""
    cleaned = raw_label.strip()
    if not cleaned:
        return None

    # Check direct dictionary match
    if cleaned in LABEL_NORMALIZATION:
        return LABEL_NORMALIZATION[cleaned]

    # Handle cp1252 / latin-1 en-dash or hyphen variations
    sanitized = cleaned.replace("\x96", "-").replace("–", "-").replace("—", "-")
    # Normalize spaces around hyphens
    sanitized = re.sub(r"\s*-\s*", " - ", sanitized)
    if "Sql Injection" in sanitized:
        sanitized = sanitized.replace("Sql Injection", "SQL Injection")

    for key, val in LABEL_NORMALIZATION.items():
        k_sanitized = key.replace("\x96", "-").replace("–", "-").replace("—", "-")
        k_sanitized = re.sub(r"\s*-\s*", " - ", k_sanitized)
        if sanitized.lower() == k_sanitized.lower():
            return val

    return sanitized


class CICDatasetStreamer:
    """Streams and audits records from the CIC-IDS2017 zip archive."""

    def __init__(self, zip_path: Path | str):
        self.zip_path = Path(zip_path)
        if not self.zip_path.exists():
            raise FileNotFoundError(f"Dataset zip archive not found at: {self.zip_path}")
        self.file_audits: Dict[str, FileAuditStats] = {}

    def get_csv_filenames(self) -> List[str]:
        """Return sorted list of CSV file names inside the zip."""
        with zipfile.ZipFile(self.zip_path, "r") as z:
            names = [n for n in z.namelist() if n.endswith(".csv")]
        return sorted(names)

    def stream_file(
        self,
        csv_filename: str,
        skip_exact_duplicates: bool = True,
        yield_raw_dict: bool = True,
    ) -> Iterator[Tuple[Dict[str, Any], str]]:
        """Stream valid records from a specific CSV file within the ZIP.

        Yields:
            (row_dict, normalized_label)
        """
        stats = FileAuditStats(filename=csv_filename)
        self.file_audits[csv_filename] = stats

        seen_exact_hashes = set()

        with zipfile.ZipFile(self.zip_path, "r") as z:
            with z.open(csv_filename, "r") as f:
                # Read header
                raw_header_line = f.readline().decode("latin-1").strip()
                stats.total_raw_lines += 1
                if not raw_header_line:
                    return

                reader = csv.reader([raw_header_line])
                raw_headers = next(reader)
                headers = clean_header(raw_headers)
                stats.header_columns_count = len(headers)
                expected_cols = len(headers)

                label_col_idx = len(headers) - 1
                dur_col_idx = headers.index("Flow Duration") if "Flow Duration" in headers else -1

                for line_bytes in f:
                    stats.total_raw_lines += 1
                    raw_str = line_bytes.decode("latin-1").strip()

                    # 1. Check for empty or blank comma-padded lines (e.g. Thursday Web Attacks padding)
                    if not raw_str or raw_str.replace(",", "") == "":
                        stats.empty_lines_dropped += 1
                        stats.exclusion_reasons["empty_or_blank_comma_row"] = (
                            stats.exclusion_reasons.get("empty_or_blank_comma_row", 0) + 1
                        )
                        continue

                    # Fast row split
                    row = raw_str.split(",")
                    if len(row) != expected_cols:
                        stats.malformed_rows_dropped += 1
                        stats.exclusion_reasons["column_count_mismatch"] = (
                            stats.exclusion_reasons.get("column_count_mismatch", 0) + 1
                        )
                        continue

                    # 2. Check and normalize label
                    raw_label = row[label_col_idx]
                    norm_label = normalize_label(raw_label)
                    if not norm_label:
                        stats.malformed_rows_dropped += 1
                        stats.exclusion_reasons["missing_or_empty_label"] = (
                            stats.exclusion_reasons.get("missing_or_empty_label", 0) + 1
                        )
                        continue

                    # 3. Check exact row duplicates
                    if skip_exact_duplicates:
                        line_hash = hash(raw_str)
                        if line_hash in seen_exact_hashes:
                            stats.exact_duplicates_count += 1
                            stats.exclusion_reasons["exact_full_row_duplicate"] = (
                                stats.exclusion_reasons.get("exact_full_row_duplicate", 0) + 1
                            )
                            continue
                        seen_exact_hashes.add(line_hash)

                    # 4. Check duration and numerical anomalies
                    has_nan_inf = False
                    for val in row:
                        val_s = val.strip()
                        if val_s in ("NaN", "Infinity", "-Infinity", "inf", "-inf"):
                            has_nan_inf = True
                            break

                    if has_nan_inf:
                        stats.nan_inf_rows_count += 1

                    if dur_col_idx >= 0:
                        try:
                            dur_val = float(row[dur_col_idx])
                            if dur_val < 0:
                                stats.negative_duration_count += 1
                            elif dur_val == 0.0:
                                stats.zero_duration_count += 1
                        except (ValueError, TypeError):
                            pass

                    stats.valid_records_yielded += 1
                    stats.label_counts[norm_label] = stats.label_counts.get(norm_label, 0) + 1

                    if yield_raw_dict:
                        row_dict = {headers[i]: row[i] for i in range(expected_cols)}
                        yield row_dict, norm_label
                    else:
                        yield row, norm_label
