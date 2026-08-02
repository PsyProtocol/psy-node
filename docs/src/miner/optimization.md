# Mining Performance Optimization

Guidelines for optimizing mining performance in the Psy network.

## Hardware Requirements

### CPU Recommendations

**For optimal performance, choose CPUs with:**
- **High core count**: 8+ cores preferred
- **AVX-512 instruction support**: Provides best performance for proof generation
- **High clock speeds**: 3.5+ GHz base frequency

**Popular choices:**
- Intel processors with AVX-512 support
- AMD processors with high core counts

**Check CPU features:**
```bash
# Verify AVX support
lscpu | grep -E "(avx|sse)"

# Check available cores
nproc
```

### Memory Requirements

- **Minimum**: 8GB RAM
- **Recommended**: 16GB+ RAM
- **High-performance setups**: 32GB+ RAM

### Storage

- Fast SSD recommended for optimal I/O performance
- Minimum 100GB free space

## Current Limitations

**GPU Acceleration**: Currently under development. GPU support will be available in future releases to significantly improve proof generation performance.

**Performance Optimization**: The miner binary handles most performance optimizations automatically. Focus on providing adequate hardware resources.

## Running Multiple Miners

You can run multiple miner instances with different wallets:

```bash
# Start multiple miners
psy_node_cli worker --config config.json --keystore-path miner1.json &
psy_node_cli worker --config config.json --keystore-path miner2.json &
psy_node_cli worker --config config.json --keystore-path miner3.json &
```

## Monitoring Performance

Monitor your miner's resource usage:

```bash
# CPU and memory usage
htop -p $(pgrep psy_node_cli)

# Check logs for performance information
tail -f miner.log
```

## Performance Tips

1. **Use dedicated hardware** for mining operations
2. **Ensure stable network connectivity** to mining endpoints
3. **Monitor system resources** to avoid bottlenecks
4. **Keep the system updated** for latest optimizations
5. **Use AVX-512 capable CPUs** when available