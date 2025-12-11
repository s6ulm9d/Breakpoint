# 🤝 Contributing to BREAKPOINT

We welcome contributions from the elite security community.

---

## 🛠️ Development Setup

1.  **Fork & Clone**:
    ```bash
    git clone https://github.com/YOUR_USER/breakpoint.git
    ```
2.  **Environment**:
    ```bash
    python -m venv .venv
    source .venv/bin/activate
    pip install -e .
    ```
3.  **Code Style**:
    - Follow PEP 8.
    - Use `black` for formatting.

---

## 🧩 Creating Attack Modules

New attacks should be added to `breakpoint/attacks/`.
Inherit from `AttackBase` and implement `execute()`.

```python
class MyNewAttack(AttackBase):
    def execute(self, target):
        # Your logic here
        pass
```

---

## 🧪 Testing

Run standard tests before submitting PRs:
```bash
python -m pytest tests/
```

---

## 📜 Code of Conduct

Maintain professionalism. No harassment. No illegal use.
