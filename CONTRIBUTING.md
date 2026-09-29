# Contributing to Bastion WAF

First off, thank you for considering contributing to Bastion WAF! 🎉

Whether you are fixing a bug, adding a new OWASP detection rule, improving semantic AST parsers, or enhancing the dashboard UI, your contributions help make Bastion WAF stronger for everyone.

---

## 🛠️ Development Setup

1. **Fork & Clone**
   ```bash
   git clone https://github.com/<your-username>/BastionWAF.git
   cd BastionWAF/waf
   ```

2. **Create Virtual Environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Verify Tests**
   ```bash
   pytest -v
   ```
   All tests must pass before making modifications.

---

## 🛡️ Adding a New Detection Rule

1. Create your rule under `waf/bastion/rules/<rule_name>.py`.
2. Inherit from `Rule` in `waf/bastion/rules/base.py`:
   ```python
   from .base import Rule, Verdict

   class MyNewRule(Rule):
       RULE_ID = "970100"
       NAME = "My Custom Threat Rule"
       CATEGORY = "Custom Threats"

       def match(self, request) -> Verdict:
           # Your inspection logic here
           return Verdict.clean(self.RULE_ID)
   ```
3. Add a corresponding test file under `waf/tests/test_<rule_name>.py` ensuring both:
   - Positive test cases (threat payloads are blocked)
   - Negative test cases (clean natural language requests are allowed without false positives)

---

## 🧪 Testing Guidelines

Before opening a pull request:
- Run the full test suite:
  ```bash
  cd waf
  pytest -v
  ```
- Ensure no runtime dependencies or database state (`waf.db`, `bank.db`, `.pyc`) are committed.

---

## 📬 Pull Request Process

1. Create a feature branch (`git checkout -b feature/awesome-detection`).
2. Commit your changes with meaningful messages (`git commit -m "feat(rules): add GraphQL batch query attack rule"`).
3. Push to your fork (`git push origin feature/awesome-detection`).
4. Open a Pull Request against `main` on `FinsterNet/BastionWAF`.
