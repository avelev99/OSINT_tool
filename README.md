# OSINT Tool - Experimental Intelligence Research Framework

## Project Status: Experimental Concept

**IMPORTANT NOTICE**: This project is currently a **work-in-progress** and represents a **conceptual exploration** of OSINT techniques and architectures. It is **not production-ready** and should be approached as an experimental research prototype. The codebase is under active development, components may be incomplete, and functionality is subject to significant changes.

## Technical Overview

The framework implements a modular architecture that decouples data collection, analysis, security, and presentation layers. The core design emphasizes:

1. **Component Isolation**: Each functional unit operates independently through well-defined interfaces, allowing for flexibility in implementation and enabling secure boundaries between components.

2. **Concurrency Management**: Analysis tasks leverage Python's asyncio framework for non-blocking I/O operations, with a custom task scheduler that prioritizes collection tasks based on resource availability and rate limiting requirements.

3. **Data Flow Architecture**: The system implements a directed acyclic graph (DAG) for data processing pipelines, ensuring deterministic transformation of raw intelligence into structured, analyzable formats.

### System Architecture

The framework consists of the following technical components:

- **Controller Layer**: Centralized orchestration through the `OSINTController` class, which dynamically initializes and manages component lifecycles
- **Collection Layer**: Scrapy-based spiders with custom downloader middlewares for traffic routing and request fingerprint diversification
- **Analysis Layer**: Graph-based relationship modeling using NetworkX with custom metrics for centrality and node importance
- **Security Layer**: Multi-layered approach involving Tor circuit management, data sanitization, and at-rest encryption
- **Persistence Layer**: Structured storage with optional encryption for collected intelligence

### Technical Implementation Details

#### Collection Mechanism

The collection system utilizes Scrapy as the foundation but extends it with:

- Custom middleware for HTML parsing optimization using lxml with XPath selectors
- Dynamic request fingerprinting to evade anti-scraping technologies
- Proxy rotation logic with integration into the Tor network
- Rate-limiting algorithms implementing exponential backoff with jitter

```python
# Example of the rate-limiting algorithm implementation
def calculate_delay(self, request, response=None):
    key = self._get_slot_key(request)
    stats = self.stats.get(key, None)
    
    if stats is None:
        stats = {'count': 0, 'last_time': 0, 'current_delay': self.min_delay}
        self.stats[key] = stats
    
    # Exponential backoff with jitter
    if time.time() - stats['last_time'] > self.reset_time:
        stats['count'] = 0
        stats['current_delay'] = self.min_delay
    else:
        stats['count'] += 1
        if stats['count'] > self.threshold:
            stats['current_delay'] = min(
                stats['current_delay'] * self.factor,
                self.max_delay
            )
            # Add jitter to avoid synchronization
            jitter = random.uniform(-0.1, 0.1) * stats['current_delay']
            stats['current_delay'] += jitter
    
    stats['last_time'] = time.time()
    return stats['current_delay']
```

#### Analysis Algorithms

The relationship mapping module implements several graph algorithms:

- Community detection using the Louvain method for identifying clusters
- Betweenness centrality for identifying bridge entities
- PageRank derivative for assessing entity importance within the network

The timeline analyzer employs:
- Temporal clustering with dynamic time warping to identify patterns
- Anomaly detection using isolation forests and time series decomposition
- Sentiment analysis with VADER for emotional content tracking

#### Security Implementation

Security is implemented through:

- Tor integration using the Stem library for circuit management
- Data sanitization with regex pattern matching for PII detection
- Encryption using AES-256 in GCM mode with key derivation via PBKDF2

```python
# Example of the encryption implementation
def encrypt_data(self, data, associated_data=None):
    # Generate a random 96-bit IV
    iv = os.urandom(12)
    
    # Create an encryptor object
    encryptor = Cipher(
        algorithms.AES(self.key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    
    # Associated data for authentication
    if associated_data:
        encryptor.authenticate_additional_data(associated_data)
    
    # Encrypt the data
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    # Return IV, ciphertext, and tag in a structured format
    return {
        'iv': base64.b64encode(iv).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'tag': base64.b64encode(encryptor.tag).decode('utf-8')
    }
```

## Experimental Features and Limitations

This framework is exploring several experimental concepts that are still under development:

1. **Cloud Bursting**: A distributed collection mechanism that scales across ephemeral cloud instances for high-volume intelligence gathering. This component uses AWS EC2 API but currently has significant limitations in error handling.

2. **Relationship Inference**: The system attempts to infer non-explicit relationships between entities using second-degree connections and semantic similarity. This feature uses experimental heuristics with varying accuracy levels.

3. **Anomaly Detection**: The anomaly detection system combines statistical outlier detection with ML-based pattern recognition, but requires further refinement and validation.

4. **Air-Gapped Operation**: Support for offline intelligence gathering and analysis is being explored but is currently incomplete.

**Known Limitations**:

- Error handling is inconsistent across modules
- Validation of collected data is preliminary
- Performance optimization is needed, especially for large datasets
- Test coverage is incomplete
- Cloud functions may encounter API rate limiting

## Development Roadmap

The project is following an iterative development approach, with current focus on:

1. Refactoring the core controller for improved error handling
2. Implementing more comprehensive unit and integration tests
3. Optimizing the relationship mapping algorithms for large graphs
4. Improving data sanitization accuracy
5. Documenting the API for potential extension

See the `roadmap.md` file for a more detailed development plan.

## Installation and Setup

### Prerequisites
- Python 3.8+
- Scrapy
- NetworkX
- Matplotlib
- Stem (for Tor integration)
- PySocks
- python-whois
- dnspython

### Development Setup
1. Clone the repository:
   ```
   git clone https://github.com/yourusername/osint_tool.git
   cd osint_tool
   ```
2. Create a virtual environment and install dependencies:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```
3. Install Tor (optional, for anonymous browsing):
   - Debian/Ubuntu: `apt install tor`
   - macOS: `brew install tor`
   - Windows: Download from [Tor Project](https://www.torproject.org/download/)

## Usage

The tool can be used through the main controller script, which provides a unified interface to all modules.

### Basic Usage
```bash
# Collect domain intelligence
python osint_tool/main.py --domain example.com

# Collect social media intelligence for a username
python osint_tool/main.py --social @username

# Analyze relationships between collected entities
python osint_tool/main.py --analyze
```

### Advanced Options
```bash
# Route traffic through Tor for anonymity
python osint_tool/main.py --domain example.com --tor

# Specify Tor exit node country
python osint_tool/main.py --domain example.com --tor --country US

# Sanitize collected data
python osint_tool/main.py --domain example.com --sanitize
```

For a complete command reference, run:
```bash
python osint_tool/main.py --help
```

## Output Structure

The tool generates several directories to organize results:
- `output/`: Raw collection results
- `reports/`: Analysis reports and visualizations
- `sanitized_output/`: Data with sensitive information redacted
- `anonymized_output/`: Data with identifiers replaced by hashes (safe for sharing)
- `logs/`: Operation logs

## Ethical Guidelines

This tool is designed for ethical use only:
- Only collect publicly available information
- Respect website terms of service and robots.txt guidelines
- Do not use for harassment, stalking, or illegal purposes
- Sanitize collected data to protect individuals' privacy
- Follow responsible disclosure for any security findings

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

This is an experimental project and contributions are welcome. Please note that as this is a conceptual exploration, substantial architectural changes may occur between versions.

## Acknowledgements

This tool builds upon various open source projects and libraries:
- [Scrapy](https://scrapy.org/) - Web crawling framework
- [NetworkX](https://networkx.org/) - Network analysis
- [Tor Project](https://www.torproject.org/) - Anonymous communication
- [python-whois](https://pypi.org/project/python-whois/) - WHOIS lookups
- [dnspython](https://www.dnspython.org/) - DNS toolkit