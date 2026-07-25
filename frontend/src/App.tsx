import { useState, useRef, useEffect } from 'react';
import aegisLogo from './assets/aegis-logo.gif';

// ---- Types ----

interface Detection {
  type: string;
  value: string;
  start: number;
  end: number;
}

interface ChatResponse {
  message: string;
  sanitized_prompt: string;
  reply: string;
  detections: Detection[];
}

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  sanitizedPrompt?: string;
  detections?: Detection[];
  timestamp: Date;
}

// ---- Helpers ----

function generateId(): string {
  return Math.random().toString(36).substring(2, 11) + Date.now().toString(36);
}

const API_BASE = '/api';

// ---- Components ----

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

function MessageBubble({ message }: { message: Message }) {
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
          {!isUser && message.detections && message.detections.length > 0 && (
            <DetectionsPanel detections={message.detections} />
          )}
          {!isUser && message.sanitizedPrompt && (
            <SanitizedPrompt prompt={message.sanitizedPrompt} />
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
        body: JSON.stringify({ message: userMessage.content }),
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

  const handleNewChat = () => {
    setMessages([]);
    setInput('');
    textareaRef.current?.focus();
  };

  return (
    <div className="app">
      <div className="clouds-container">
        <div className="sunbeam sunbeam-1"></div>
        <div className="sunbeam sunbeam-2"></div>
        <div className="sunbeam sunbeam-3"></div>
        <div className="sunbeam sunbeam-4"></div>
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
                <MessageBubble key={msg.id} message={msg} />
              ))}
              {isLoading && <LoadingIndicator />}
              <div ref={messagesEndRef} />
            </div>
          )}
        </div>

        <div className="input-area">
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
    </div>
  );
}
