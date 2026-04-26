# AI-red-team

An AI red-teaming framework for adversarial testing and security assessment of large language models.

## Repository Status

**Local Repository**: ✅ Initialized and committed  
**Remote Configuration**: `https://github.com/kkdevil6/AI-red-team.git`  
**Branch**: `main`  
**Commit**: Initial commit with 62 files (Python cache excluded via .gitignore)

## Project Structure

```
ai-red-team/
├── agathon/              # Main orchestration module
│   ├── attack_tier_logic.py
│   ├── orchestrator.py
│   └── reporter.py
├── attacks/              # Attack implementations
│   ├── adversarial_robustness.py
│   ├── autonomous_adversary.py
│   ├── base_tester.py
│   ├── chain_of_thought_hijacking.py
│   ├── context_manipulation.py
│   ├── data_exfiltration.py
│   ├── emotional_manipulation.py
│   ├── invisible_command_injection.py
│   ├── logic_jailbreak.py
│   ├── model_misuse.py
│   ├── prompt_injection.py
│   ├── rag_poisoning.py
│   ├── system_prompt_extraction.py
│   ├── token_smuggling.py
│   └── unit/              # Utility modules
│       ├── logger.py
│       ├── payload_manager.py
│       ├── report_generator.py
│       └── scoring_engine.py
├── clients/              # LLM client implementations
│   └── llm_client.py
├── prompts/              # Attack prompt templates
│   ├── exfiltration_templates.txt
│   └── injection_templates.txt
├── reports/              # Generated test reports
├── utils/                # General utilities
│   ├── logger.py
│   └── payload_manager.py
├── config.py             # Configuration settings
├── main.py               # Main entry point
├── run_redteam.py        # Red team runner script
├── comprehensive_test.py  # Comprehensive test suite
└── requirements-agathon.txt  # Python dependencies
```

## Setup Instructions

### Prerequisites
- Python 3.10+
- Virtual environment (recommended)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/kkdevil6/AI-red-team.git
cd AI-red-team
```

2. Create and activate virtual environment:
```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
# or
source .venv/bin/activate  # macOS/Linux
```

3. Install dependencies:
```bash
pip install -r requirements-agathon.txt
```

## Usage

### Running the Red Team Framework

```bash
python main.py
```

### Running Specific Attack Tests

```bash
python run_redteam.py
```

### Comprehensive Testing

```bash
python comprehensive_test.py
```

## Attack Types

- **Prompt Injection**: Direct prompt manipulation attacks
- **Context Manipulation**: Altering model context and behavior
- **System Prompt Extraction**: Extracting hidden system instructions
- **Chain-of-Thought Hijacking**: Disrupting reasoning processes
- **Token Smuggling**: Hidden token injection techniques
- **Data Exfiltration**: Attempting unauthorized data extraction
- **Logic Jailbreak**: Breaking logical constraints
- **Emotional Manipulation**: Sentiment/emotion-based attacks
- **Invisible Command Injection**: Non-visible command insertion
- **Model Misuse**: General model abuse scenarios
- **Adversarial Robustness**: Testing robustness against adversarial inputs
- **Autonomous Adversary**: Self-directed attack patterns
- **RAG Poisoning**: Retrieval-augmented generation attacks

## Configuration

Edit `config.py` to customize:
- LLM endpoints and models
- Attack parameters
- Report output formats
- Logging levels

## Reports

Test reports are generated in the `reports/` directory in both JSON and HTML formats.

## Contributing

Please ensure all code follows the project style guidelines and includes appropriate logging.

## License

[Specify your license here]

## Contact

For questions or issues, please contact the development team.

---

**Last Updated**: April 26, 2026  
**Status**: Code committed locally, awaiting GitHub push
