# Aegis Shield

Zero-trust AI security gateway that detects and protects sensitive data before it reaches external LLMs.

## What It Does

Aegis Shield sits between you and the AI model. Every message is scanned for 20+ categories of sensitive information (PII, financial data, secrets, medical records), masked with placeholders before being sent to the LLM, then restored in the response. The model never sees your real data.

### Detected Categories

- **Personal:** Names, emails, phone numbers, addresses, dates of birth
- **Financial:** Credit cards, SSNs, bank accounts, salaries, credit scores, monetary amounts
- **Secrets:** API keys (OpenAI, AWS, GitHub), passwords, JWTs, tokens
- **Medical:** MRNs, ICD codes, NPI numbers, insurance policy numbers
- **Business:** Customer IDs, confidential labels, organization names, IP addresses

## Architecture

```
User Input --> Detector (regex + spaCy NER) --> Placeholder Masking
    --> LLM (Ollama, local) --> Response Sanitization --> Placeholder Restoration --> User
```

- **Frontend:** React + TypeScript + Vite
- **Backend:** Python HTTP server (stdlib)
- **Detection:** spaCy NER + 20+ regex patterns
- **LLM:** Ollama (llama3.2, runs locally)

## Setup

### Prerequisites

- Python 3.10+
- Node.js 18+
- [Ollama](https://ollama.ai) with a model pulled:
  ```bash
  ollama pull llama3.2
  ```

### Install

```bash
# Python dependencies
pip install -r requirements.txt
python -m spacy download en_core_web_sm

# Frontend
cd frontend
npm install
npm run build
cd ..
```

### Run

**Windows:**
```bash
start.bat
```

**Linux / macOS:**
```bash
bash start.sh
```

Then open **http://localhost:8080**.

### Run Tests

```bash
pytest tests/ -v
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | Server port |
| `OLLAMA_MODEL` | `llama3.2:latest` | Ollama model name |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama API base URL |
| `OLLAMA_TIMEOUT` | `30` | Request timeout in seconds |

## License

See [LICENSE](LICENSE).
