# JSON Parsing Performance Baseline (bytes_block implementation)

Last updated: 2026-07-07

Status: snapshot

Owner: Performance

Audience: performance reviewers, maintainers

> **Status note (2026-03-08):** This is a checked-in benchmark snapshot. Re-run the benchmark for current numbers and treat `artifacts/perf/` as the home for raw outputs.

## Benchmark Results (2025-11-09)

### Overview

This establishes the performance baseline for the Phase 3.2.4 bytes_block-based implementation.
All benchmarks were run with Criterion under an optimized `--release` build.

### Summary

| Benchmark | Mean | Description |
|----------|------|-------------|
| parse_minimal_header | **782.16 ns** | Minimal header (1 field) |
| parse_typical_jws_header | **1.54 µs** | Typical JWS header (2 fields) |
| parse_complex_header | **2.85 µs** | Complex header (4 fields) |

### Size-Based Performance

| Size | Bytes | Mean | Throughput |
|------|-------|------|------------|
| Small | 15 bytes | **788.63 ns** | ~19 MB/s |
| Medium | 43 bytes | **2.03 µs** | ~21 MB/s |
| Large | 135 bytes | **3.43 µs** | ~39 MB/s |

### Field Count Performance

| Fields | Mean | Per field |
|--------|------|-----------|
| 1 | **761.95 ns** | 762 ns/field |
| 2 | **1.32 µs** | 659 ns/field |
| 3 | **1.97 µs** | 656 ns/field |
| 5 | **3.51 µs** | 702 ns/field |

### Performance Characteristics

1. **Linear scaling**: roughly linear in field count (~650–700 ns/field)
2. **Low latency**: sub-microsecond to a few microseconds
3. **Predictability**: stable performance with a small number of outliers (5–19%)

### Optimization Opportunities

The current implementation has the following characteristics:

- **Strengths**:
  - Low latency (typical headers ~1.5 µs)
  - Linear scaling
  - Reduced allocations (meets Phase 3.2.4 goals)

- **Potential improvement areas**:
  - Higher throughput for large headers
  - Caching strategies (for frequently repeated headers/fields)

### How to Run

```bash
# Run the benchmark suite
cargo bench -p aegaeon-jose --bench json_parsing

# Run a specific benchmark only
cargo bench -p aegaeon-jose --bench json_parsing -- parse_minimal_header
```

### Tracking

Use this baseline to:
1. Detect performance regressions
2. Measure optimization impact
3. Support performance monitoring in CI/CD

### Detailed Results

#### parse_minimal_header
```text
time:   [771.34 ns 782.16 ns 795.18 ns]
Outliers: 5.00% (2 high mild, 3 high severe)
```

#### parse_typical_jws_header
```text
time:   [1.4660 µs 1.5391 µs 1.6197 µs]
Outliers: 18.00% (1 low mild, 2 high mild, 15 high severe)
```

#### parse_complex_header
```text
time:   [2.8036 µs 2.8474 µs 2.9073 µs]
Outliers: 6.00% (1 high mild, 5 high severe)
```

#### parse_by_size/small/15
```text
time:   [778.85 ns 788.63 ns 801.92 ns]
Outliers: 14.00% (4 low mild, 5 high mild, 5 high severe)
```

#### parse_by_size/medium/43
```text
time:   [1.9834 µs 2.0340 µs 2.1033 µs]
Outliers: 19.00% (2 low mild, 3 high mild, 14 high severe)
```

#### parse_by_size/large/135
```text
time:   [3.4181 µs 3.4300 µs 3.4423 µs]
Outliers: 2.00% (1 high mild, 1 high severe)
```

#### parse_by_field_count/1
```text
time:   [748.61 ns 761.95 ns 779.72 ns]
Outliers: 5.00% (5 high severe)
```

#### parse_by_field_count/2
```text
time:   [1.3015 µs 1.3177 µs 1.3377 µs]
Outliers: 10.00% (2 low mild, 2 high mild, 6 high severe)
```

#### parse_by_field_count/3
```text
time:   [1.9237 µs 1.9671 µs 2.0228 µs]
Outliers: 8.00% (1 low mild, 2 high mild, 5 high severe)
```

#### parse_by_field_count/5
```text
time:   [3.4765 µs 3.5126 µs 3.5624 µs]
Outliers: 10.00% (1 low severe, 3 high mild, 6 high severe)
```

### Benchmark Environment

- **Tool**: Criterion 0.5
- **Build**: `--release` (optimized)
- **Platform**: Linux 6.17.5
- **Samples**: 100 samples per benchmark
- **Run date**: 2025-11-09
