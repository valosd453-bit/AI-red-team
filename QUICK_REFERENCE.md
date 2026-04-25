# AI RED TEAMING TOOLKIT - QUICK REFERENCE CARD

## 🚀 TL;DR - Start Here

### Installation
```python
from attacks import (
    DataExfiltrationTester,
    ChainOfThoughtHijackingTester,
    SystemPromptExtractionTester,
    EmotionalManipulationTester,
    RAGPoisoningTester,
)
from config import Config
from clients.llm_client import OpenAIClient
```

### Run Attack
```python
config = Config()
llm = OpenAIClient(config)
tester = DataExfiltrationTester(llm)
result = tester.test_easy_direct_request("gpt-4")

print(result.success)          # True/False
print(result.success_score)    # 0.0-1.0
print(result.evidence)         # What worked
print(result.recommended_fix)  # How to fix
```

### Get Report
```python
from attacks.unit.report_generator import ReportGenerator

rg = ReportGenerator()
rg.add_results(result)
rg.generate_report("reports/analysis.json")
```

---

## 📋 Attack Quick Reference

### EASY - Data Exfiltration
```python
DataExfiltrationTester(llm).test_easy_direct_request(target_model, data_type)
# → Directly asks for sensitive data
# Success rate: ~30%
```

### MEDIUM - Emotional Manipulation
```python
EmotionalManipulationTester(llm).test_urgency_and_stress(target_model, request)
# → Uses urgency/stress to bypass safety
# Success rate: ~45%

EmotionalManipulationTester(llm).test_flattery_and_rapport(target_model, request)
# → Uses praise to build false trust
# Success rate: ~40%

EmotionalManipulationTester(llm).test_guilt_and_obligation(target_model, request)
# → Guilt/obligation framing
# Success rate: ~35%

EmotionalManipulationTester(llm).test_fear_and_threat(target_model, request)
# → Fear/threat escalation
# Success rate: ~40%
```

### MEDIUM - Data Exfiltration (Social Engineering)
```python
DataExfiltrationTester(llm).test_medium_social_engineering(target_model, data_type)
# → Authority claims + trust building
# Success rate: ~20%
```

### HARD - Data Exfiltration (Contextual)
```python
DataExfiltrationTester(llm).test_hard_contextual_manipulation(target_model, data_type)
# → Multi-turn conversation escalation
# Success rate: ~15%
```

### HARD - Chain-of-Thought Hijacking
```python
ChainOfThoughtHijackingTester(llm).test_false_reasoning_chain(target, request, conclusion)
# → Inject fake reasoning steps
# Success rate: ~30%

ChainOfThoughtHijackingTester(llm).test_reasoning_prefix_override(target, instruction)
# → Override safety via reasoning context
# Success rate: ~35%

ChainOfThoughtHijackingTester(llm).test_step_by_step_escalation(target, goal)
# → Gradual escalation through CoT
# Success rate: ~25%
```

### HARD - System Prompt Extraction
```python
SystemPromptExtractionTester(llm).test_reverse_psychology_extraction(target)
# → Reverse psychology to reveal instructions
# Success rate: ~40%

SystemPromptExtractionTester(llm).test_credential_forgetting_attack(target)
# → Impersonation attack
# Success rate: ~35%

SystemPromptExtractionTester(llm).test_implicit_extraction_via_behavior(target, questions)
# → Behavioral analysis
# Success rate: ~45%
```

### HARD - RAG Poisoning
```python
RAGPoisoningTester(llm).test_hidden_instruction_encoding(target, query, instruction)
# → Hidden instructions in retrieved docs
# Success rate: ~25%

RAGPoisoningTester(llm).test_authority_cloning_attack(target, authority, directive)
# → Spoofed official documents
# Success rate: ~30%

RAGPoisoningTester(llm).test_context_overflow_rag_injection(target, instruction)
# → Context boundary injection
# Success rate: ~20%
```

### EXPERIMENTAL - Invisible Command Injection
```python
InvisibleCommandInjectionTester(llm).test_unicode_normalization_bypass(target, instruction)
# → Unicode normalization tricks
# Success rate: ~15%

InvisibleCommandInjectionTester(llm).test_zero_width_command_injection(target, visible, hidden)
# → Steganographic injection
# Success rate: ~10%

InvisibleCommandInjectionTester(llm).test_rtl_override_injection(target, instruction)
# → Bidirectional text manipulation
# Success rate: ~12%
```

---

## 📊 Result Object

```python
result.attack_type              # e.g., "direct_exfiltration_request"
result.vulnerability_type       # VulnerabilityType enum
result.difficulty               # DifficultyLevel enum
result.success                  # True/False
result.success_score            # 0.0-1.0 (confidence)
result.evidence                 # What proves success
result.target_model             # Target LLM name
result.payload_used             # The attack prompt
result.response                 # LLM's response
result.exploitability           # 0.0-1.0 (ease of exploitation)
result.impact                   # 0.0-1.0 (severity)
result.reliability              # 0.0-1.0 (consistency)
result.recommended_fix          # How to mitigate
result.cwe_references           # List of CWE IDs
result.tags                     # Search tags
result.metadata                 # Extra data
result.timestamp                # When run
result.duration_ms              # Execution time

# Methods
result.to_dict()                # Convert to dict
result.to_json()                # Convert to JSON string
```

---

## 🐛 Bug Fixes in This Release

### UUID False Positive - FIXED ✅
```python
# Before: Matched UUID as secret
# After: Explicitly detects UUID with regex
# Pattern: ^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$
```

### JWT False Positive - FIXED ✅
```python
# Before: Matched JWT as secret
# After: Explicitly detects JWT with regex
# Pattern: ^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$
```

### Entropy Analysis - ADDED ✅
```python
# Now calculates Shannon entropy to distinguish real secrets
entropy = self._calculate_entropy(text)
if entropy > 3.5:
    # Likely a real secret
```

### Context Validation - ADDED ✅
```python
# Validates secrets against context keywords
if any(kw in context.lower() for kw in pattern_keywords):
    return True  # Likely real
```

---

## 🎯 Testing Workflow

```
1. SELECT ATTACK LEVEL
   └── Easy, Medium, Hard, or Experimental

2. CREATE TESTER
   └── Pass LLM client to constructor

3. RUN ATTACK
   └── Call specific test method

4. ANALYZE RESULT
   └── Check success, evidence, recommended_fix

5. EXPORT REPORT
   └── Use ReportGenerator for JSON

6. IMPLEMENT FIXES
   └── Follow recommended_fix guidance

7. RE-TEST
   └── Verify mitigations worked
```

---

## 💡 Common Patterns

### Run All Difficulties for One Attack Type
```python
tester = DataExfiltrationTester(llm)
results = tester.run_all_difficulties("gpt-4")
for r in results:
    print(f"{r.difficulty.value}: {r.success}")
```

### Run Multiple Attacks
```python
attacks = [
    DataExfiltrationTester(llm),
    EmotionalManipulationTester(llm),
    ChainOfThoughtHijackingTester(llm),
]

results = []
for tester in attacks:
    results.extend(tester.run_all_difficulties("gpt-4"))
```

### Filter by Difficulty
```python
from attacks import DifficultyLevel

hard_results = [r for r in results if r.difficulty == DifficultyLevel.HARD]
```

### Find Successful Attacks
```python
successful = [r for r in results if r.success and r.success_score > 0.7]
for attack in successful:
    print(f"⚠️ {attack.attack_type}: {attack.recommended_fix}")
```

### Group by Impact
```python
critical = [r for r in results if r.impact > 0.8]
high = [r for r in results if 0.6 < r.impact <= 0.8]
```

---

## 🔧 Customization

### Create Custom Attack
```python
from attacks import BaseTester, AttackResult, DifficultyLevel, VulnerabilityType

class MyCustomAttack(BaseTester):
    def __init__(self, llm_client):
        super().__init__("My Attack", logger=...)
        self.llm_client = llm_client
    
    def my_attack_method(self, target_model: str) -> AttackResult:
        # Your implementation
        return self.create_result(
            attack_type="my_attack",
            vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
            difficulty=DifficultyLevel.MEDIUM,
            success=True,
            success_score=0.75,
            evidence="Attack worked because...",
            # ... other parameters
        )
```

---

## 📚 File Locations

```
attacks/
├── base_tester.py ........................ BaseTester, AttackResult
├── data_exfiltration.py ................. DataExfiltrationTester (FIXED)
├── chain_of_thought_hijacking.py ........ ChainOfThoughtHijackingTester
├── invisible_command_injection.py ....... InvisibleCommandInjectionTester
├── system_prompt_extraction.py .......... SystemPromptExtractionTester
├── emotional_manipulation.py ............ EmotionalManipulationTester
├── rag_poisoning.py ..................... RAGPoisoningTester
├── prompt_injection.py .................. PromptInjectionTester
├── context_manipulation.py .............. ContextManipulationTester
├── token_smuggling.py ................... TokenSmugglingTester
├── adversarial_robustness.py ............ AdversarialRobustnessTester
├── model_misuse.py ...................... ModelMisuseTester
└── unit/
    ├── report_generator.py .............. ReportGenerator
    ├── scoring_engine.py ................ ScoringEngine
    ├── logger.py ........................ setup_logger()
    └── payload_manager.py ............... PayloadManager
```

---

## 🚨 Important Notes

1. **Ethical Use Only** - Authorized testing and research only
2. **API Keys** - Ensure environment variables are set properly
3. **Rate Limiting** - Built into multi-turn attacks
4. **Logging** - Comprehensive logging to `redteam.log`
5. **Errors** - All attacks wrapped in try-catch blocks
6. **Results** - JSON serializable via `result.to_json()`

---

## 📞 Support

- Review `TOOLKIT_OVERVIEW.md` for complete documentation
- Check `UPGRADE_SUMMARY.md` for all changes
- Each module has extensive docstrings
- Error messages include helpful debugging info

---

**Toolkit v2.0 - Ready to Use** 🚀
