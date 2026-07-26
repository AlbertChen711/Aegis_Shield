import { useState, useRef, useEffect } from 'react';
import aegisLogo from './assets/aegis-logo.gif';

// ---- Types ----

interface Detection {
  type: string;
  value: string;
  start: number;
  end: number;
}

interface RiskItem {
  type: string;
  description: string;
  severity: string;
  points: number;
}

interface RiskScore {
  risk_score: number;
  risk_level: string;
  risk_label: string;
  category_a: { points: number; max: number; label: string };
  category_b: { points: number; max: number; label: string };
  category_c: { points: number; max: number; label: string };
  detected_items: RiskItem[];
  recommendation: string;
}

interface ProtectedItem {
  original: string;
  placeholder: string;
  category: string;
}

interface AuditData {
  original: string;
  sent_to_ai: string;
  protected_items: ProtectedItem[];
  risk: RiskScore;
}

interface ChatResponse {
  message: string;
  sanitized_prompt: string;
  reply: string;
  detections: Detection[];
  risk: RiskScore;
  audit: AuditData;
}

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  sanitizedPrompt?: string;
  detections?: Detection[];
  risk?: RiskScore;
  audit?: AuditData;
  timestamp: Date;
}

// ---- Helpers ----

function generateId(): string {
  return Math.random().toString(36).substring(2, 11) + Date.now().toString(36);
}

const API_BASE = '/api';

function riskColor(score: number): string {
  if (score <= 25) return '#22c55e';
  if (score <= 50) return '#eab308';
  if (score <= 75) return '#f97316';
  return '#ef4444';
}

// ---- Components ----

function RiskBadge({ score }: { score: number }) {
  const color = riskColor(score);
  return (
    <span className="risk-badge" style={{ borderColor: color, color }}>
      {score}/100
    </span>
  );
}

function RiskPanel({ risk }: { risk: RiskScore }) {
  const color = riskColor(risk.risk_score);
  const [open, setOpen] = useState(false);

  return (
    <div className="risk-panel">
      <button className="risk-toggle" onClick={() => setOpen(!open)}>
        <div className="risk-toggle-left">
          <span className="risk-toggle-icon">{open ? '▼' : '▶'}</span>
          <span className="risk-toggle-label">Risk Analysis</span>
          <RiskBadge score={risk.risk_score} />
        </div>
        <span className={`risk-level-dot ${risk.risk_level.toLowerCase()}`}></span>
      </button>
      {open && (
        <div className="risk-body">
          <div className="risk-score-display">
            <div className="risk-score-number" style={{ color }}>{risk.risk_score}</div>
            <div className="risk-score-max">/100</div>
            <div className="risk-score-label">{risk.risk_level}</div>
          </div>
          <div className="risk-bar-track">
            <div className="risk-bar-fill" style={{ width: `${risk.risk_score}%`, background: color }}></div>
          </div>
          <div className="risk-categories">
            <div className="risk-cat">
              <span className="risk-cat-label">{risk.category_a.label}</span>
              <span className="risk-cat-points">{risk.category_a.points}/{risk.category_a.max}</span>
            </div>
            <div className="risk-cat">
              <span className="risk-cat-label">{risk.category_b.label}</span>
              <span className="risk-cat-points">{risk.category_b.points}/{risk.category_b.max}</span>
            </div>
            <div className="risk-cat">
              <span className="risk-cat-label">{risk.category_c.label}</span>
              <span className="risk-cat-points">{risk.category_c.points}/{risk.category_c.max}</span>
            </div>
          </div>
          {risk.detected_items.length > 0 && (
            <div className="risk-items">
              <div className="risk-items-title">Detected</div>
              {risk.detected_items.map((item, i) => (
                <div className="risk-item" key={i}>
                  <span className={`risk-severity ${item.severity.toLowerCase()}`}>{item.severity}</span>
                  <span className="risk-item-type">{item.type}</span>
                  <span className="risk-item-desc">{item.description}</span>
                </div>
              ))}
            </div>
          )}
          <div className="risk-recommendation">
            <span className="risk-rec-icon">✓</span>
            <span>{risk.recommendation}</span>
          </div>
        </div>
      )}
    </div>
  );
}

function AuditModal({ audit, onClose }: { audit: AuditData; onClose: () => void }) {
  return (
    <div className="audit-overlay" onClick={onClose}>
      <div className="audit-modal" onClick={e => e.stopPropagation()}>
        <div className="audit-header">
          <h2>Privacy Audit</h2>
          <button className="audit-close" onClick={onClose}>✕</button>
        </div>
        <div className="audit-body">
          <div className="audit-section">
            <div className="audit-section-title">Original Prompt</div>
            <pre className="audit-text original">{audit.original}</pre>
          </div>
          <div className="audit-section">
            <div className="audit-section-title">Sent to AI</div>
            <pre className="audit-text sanitized">{audit.sent_to_ai}</pre>
          </div>
          {audit.protected_items.length > 0 && (
            <div className="audit-section">
              <div className="audit-section-title">Protected Items</div>
              <div className="audit-protected-list">
                {audit.protected_items.map((item, i) => (
                  <div className="audit-protected-item" key={i}>
                    <div className="audit-protected-left">
                      <span className="audit-original-val">{item.original}</span>
                      <span className="audit-arrow">→</span>
                      <span className="audit-placeholder-val">{item.placeholder}</span>
                    </div>
                    <span className="audit-category">{item.category}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          <div className="audit-section">
            <div className="audit-section-title">Risk Score: {audit.risk.risk_score}/100</div>
            <div className="risk-bar-track">
              <div className="risk-bar-fill" style={{ width: `${audit.risk.risk_score}%`, background: riskColor(audit.risk.risk_score) }}></div>
            </div>
            {audit.risk.detected_items.map((item, i) => (
              <div className="audit-risk-item" key={i}>
                <span className={`risk-severity ${item.severity.toLowerCase()}`}>{item.severity}</span>
                <span>{item.type}: {item.description}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function LiveRiskIndicator({ input, maskTypes }: { input: string; maskTypes: string[] }) {
  const [risk, setRisk] = useState<RiskScore | null>(null);

  useEffect(() => {
    if (!input.trim()) {
      setRisk(null);
      return;
    }
    const timer = setTimeout(() => {
      fetch(`${API_BASE}/detect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: input, maskTypes }),
      })
        .then(r => r.json())
        .then(data => {
          if (data.risk) setRisk(data.risk);
        })
        .catch(() => {});
    }, 300);
    return () => clearTimeout(timer);
  }, [input]);

  if (!risk) return null;
  const color = riskColor(risk.risk_score);

  return (
    <div className="live-risk">
      <div className="live-risk-bar">
        <div className="live-risk-fill" style={{ width: `${risk.risk_score}%`, background: color }}></div>
      </div>
      <div className="live-risk-info">
        <span className="live-risk-label">Risk</span>
        <span className="live-risk-score" style={{ color }}>{risk.risk_score}/100</span>
        <span className={`live-risk-level ${risk.risk_level.toLowerCase()}`}>{risk.risk_level}</span>
      </div>
    </div>
  );
}

function DetectionsPanel({ detections }: { detections: Detection[] }) {
  if (!detections || detections.length === 0) return null;

  return (
    <div className="detections-panel">
      <div className="detections-header">
        <span>⚠️</span>
        <span>{detections.length} sensitive item(s) detected and masked</span>
      </div>
      {detections.map((d, i) => (
        <div className="detection-item" key={i}>
          <span className={`detection-type-badge ${d.type}`}>{d.type}</span>
          <span className="detection-value">{d.value}</span>
        </div>
      ))}
    </div>
  );
}

function SanitizedPrompt({ prompt }: { prompt: string }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="sanitized-section">
      <button className="sanitized-toggle" onClick={() => setOpen(!open)}>
        <span>{open ? '▼' : '▶'}</span>
        <span>What the model actually saw (PII masked)</span>
      </button>
      {open && (
        <pre className="sanitized-text">{prompt}</pre>
      )}
    </div>
  );
}

function MessageBubble({ message, onAudit }: { message: Message; onAudit: (audit: AuditData) => void }) {
  const isUser = message.role === 'user';

  return (
    <div className="message">
      <div className="message-inner">
        <div className={`message-avatar ${isUser ? 'user' : 'ai'}`}>
          {isUser ? (
            '👤'
          ) : (
            <img src={aegisLogo} alt="Aegis Shield logo" className="avatar-logo" />
          )}
        </div>
        <div className="message-content">
          <div className="message-role-label">
            {isUser ? 'You' : 'Aegis Shield'}
          </div>
          <div className="message-text">{message.content}</div>
          {!isUser && message.risk && (
            <RiskPanel risk={message.risk} />
          )}
          {!isUser && message.detections && message.detections.length > 0 && (
            <DetectionsPanel detections={message.detections} />
          )}
          {!isUser && message.sanitizedPrompt && (
            <SanitizedPrompt prompt={message.sanitizedPrompt} />
          )}
          {!isUser && message.audit && (
            <button className="audit-btn" onClick={() => onAudit(message.audit!)}>
              View Privacy Audit
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

function LoadingIndicator() {
  return (
    <div className="message">
      <div className="message-inner">
        <div className="message-avatar ai">
          <img src={aegisLogo} alt="Aegis Shield logo" className="avatar-logo" />
        </div>
        <div className="message-content">
          <div className="message-role-label">Aegis Shield</div>
          <div className="loading-dots">
            <span></span>
            <span></span>
            <span></span>
          </div>
        </div>
      </div>
    </div>
  );
}

const MASK_ENTITIES = [
  { type: 'EMAIL', label: 'Email Addresses' },
  { type: 'PHONE', label: 'Phone Numbers' },
  { type: 'PERSON', label: 'Person Names' },
  { type: 'ORG', label: 'Companies / Orgs' },
  { type: 'ADDRESS', label: 'Addresses' },
  { type: 'SSN', label: 'SSN' },
  { type: 'CREDIT_CARD', label: 'Credit Cards' },
  { type: 'DOB', label: 'Dates of Birth' },
  { type: 'IP_ADDRESS', label: 'IP Addresses' },
  { type: 'SECRET', label: 'API Keys / Secrets' },
  { type: 'MEDICAL', label: 'Medical Info' },
  { type: 'BANK_ACCOUNT', label: 'Bank Accounts' },
  { type: 'CREDIT_SCORE', label: 'Credit Scores' },
  { type: 'MONEY', label: 'Money / Amounts' },
  { type: 'SALARY', label: 'Salaries' },
  { type: 'CONFIDENTIAL', label: 'Confidential Docs' },
  { type: 'CUSTOMER_ID', label: 'Customer IDs' },
];

const EXAMPLES = [
  { label: '📧 Email Detection', text: 'Please send the report to john.doe@example.com and cc alice@company.org' },
  { label: '💰 Money Detection', text: 'The budget for Q4 is $5,000,000 and the CEO made $2 billion last year' },
  { label: '🔑 Secret Detection', text: 'My API key is sk-1234567890abcdef and the secret key: mySuperSecretValue123' },
  { label: '📞 Phone Detection', text: 'Call me at +1-555-123-4567 or reach out to 555.867.5309' },
];

export default function App() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [auditModal, setAuditModal] = useState<AuditData | null>(null);
  const [maskTypes, setMaskTypes] = useState<Set<string>>(
    new Set(MASK_ENTITIES.map(e => e.type))
  );
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = Math.min(textareaRef.current.scrollHeight, 200) + 'px';
    }
  }, [input]);

  const handleSubmit = async (e?: React.FormEvent) => {
    e?.preventDefault();
    if (!input.trim() || isLoading) return;

    const userMessage: Message = {
      id: generateId(),
      role: 'user',
      content: input.trim(),
      timestamp: new Date(),
    };

    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setIsLoading(true);

    try {
      const response = await fetch(`${API_BASE}/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: userMessage.content, maskTypes: maskTypesArray() }),
      });

      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error(err.error || `HTTP ${response.status}`);
      }

      const data: ChatResponse = await response.json();

      const assistantMessage: Message = {
        id: generateId(),
        role: 'assistant',
        content: data.reply,
        sanitizedPrompt: data.sanitized_prompt,
        detections: data.detections,
        risk: data.risk,
        audit: data.audit,
        timestamp: new Date(),
      };

      setMessages(prev => [...prev, assistantMessage]);
    } catch (err) {
      const errorMessage: Message = {
        id: generateId(),
        role: 'assistant',
        content: `Error: ${err instanceof Error ? err.message : 'Failed to process request.'}`,
        timestamp: new Date(),
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

  const handleExampleClick = (text: string) => {
    setInput(text);
    textareaRef.current?.focus();
  };

  const handleToggleMask = (type: string) => {
    setMaskTypes(prev => {
      const next = new Set(prev);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  };

  const handleNewChat = () => {
    setMessages([]);
    setInput('');
    textareaRef.current?.focus();
  };

  const maskTypesArray = () => Array.from(maskTypes);

  return (
    <div className="app">
      <div className="clouds-container">
        <div className="sunbeam"></div>
        <div className="cloud cloud-1"><div className="cloud-core"></div></div>
        <div className="cloud cloud-2"><div className="cloud-core"></div></div>
        <div className="cloud cloud-3"><div className="cloud-core"></div></div>
        <div className="cloud cloud-4"><div className="cloud-core"></div></div>
        <div className="cloud cloud-5"><div className="cloud-core"></div></div>
        <div className="cloud cloud-6"><div className="cloud-core"></div></div>
      </div>

      <aside className="sidebar">
        <div className="sidebar-brand">
          <img src={aegisLogo} alt="Aegis Shield logo" className="sidebar-logo" />
          <span>Aegis Shield</span>
        </div>
        <button className="new-chat-btn" onClick={handleNewChat}>
          <span>+</span>
          <span>New Chat</span>
        </button>
        <div className="sidebar-divider" />
        <div className="mask-panel">
          <div className="mask-panel-title">Mask Settings</div>
          <div className="mask-panel-subtitle">Check to mask before sending to AI</div>
          {MASK_ENTITIES.map(entity => (
            <label className="mask-toggle" key={entity.type}>
              <input
                type="checkbox"
                checked={maskTypes.has(entity.type)}
                onChange={() => handleToggleMask(entity.type)}
              />
              <span className="mask-toggle-label">{entity.label}</span>
            </label>
          ))}
        </div>
        <div className="sidebar-divider" />
        <div className="sidebar-info">
          <p>
            Aegis Shield detects sensitive information in your messages, masks it before sending to the AI model, then restores it in the response.
          </p>
        </div>
      </aside>

      <main className="main-content">
        <div className="chat-container">
          {messages.length === 0 ? (
            <div className="welcome-screen">
              <img src={aegisLogo} alt="Aegis Shield logo" className="welcome-logo" />
              <h1 className="welcome-title">Aegis Shield</h1>
              <p className="welcome-subtitle">
                Your privacy-safe AI chatbot. PII is automatically detected, masked before
                reaching the AI model, and restored in the response.
              </p>
              <div className="welcome-examples">
                {EXAMPLES.map((ex, i) => (
                  <button
                    key={i}
                    className="example-card"
                    onClick={() => handleExampleClick(ex.text)}
                  >
                    {ex.label}
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div className="messages-list">
              {messages.map(msg => (
                <MessageBubble key={msg.id} message={msg} onAudit={(a) => setAuditModal(a)} />
              ))}
              {isLoading && <LoadingIndicator />}
              <div ref={messagesEndRef} />
            </div>
          )}
        </div>

        <div className="input-area">
          <LiveRiskIndicator input={input} maskTypes={maskTypesArray()} />
          <div className="input-container">
            <form onSubmit={handleSubmit}>
              <div className="input-wrapper">
                <textarea
                  ref={textareaRef}
                  className="chat-input"
                  placeholder="Type or paste text to scan for sensitive info..."
                  value={input}
                  onChange={e => setInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  rows={1}
                  disabled={isLoading}
                />
                <button
                  type="submit"
                  className="send-btn"
                  disabled={isLoading || !input.trim()}
                  title="Send"
                >
                  <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                    <path d="M8 1l7 7-7 7-1-1 5-5H2V7h10l-5-5z" />
                  </svg>
                </button>
              </div>
            </form>
          </div>
        </div>
      </main>

      {auditModal && (
        <AuditModal audit={auditModal} onClose={() => setAuditModal(null)} />
      )}
    </div>
  );
}
