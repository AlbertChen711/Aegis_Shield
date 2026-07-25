import { useState, useRef, useEffect } from 'react';

// ---- Types ----

interface Detection {
  type: string;
  value: string;
  start: number;
  end: number;
}

interface ChatResponse {
  message: string;
  detections: Detection[];
  summary: {
    total: number;
    by_type: Record<string, number>;
  };
  reply: string;
}

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
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
        <span>{detections.length} sensitive item(s) detected</span>
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

function MessageBubble({ message }: { message: Message }) {
  const isUser = message.role === 'user';

  return (
    <div className="message">
      <div className="message-inner">
        <div className={`message-avatar ${isUser ? 'user' : 'ai'}`}>
          {isUser ? '👤' : '🛡️'}
        </div>
        <div className="message-content">
          <div className="message-role-label">
            {isUser ? 'You' : 'Aegis Shield'}
          </div>
          <div className="message-text">{message.content}</div>
          {!isUser && message.detections && (
            <DetectionsPanel detections={message.detections} />
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
        <div className="message-avatar ai">🛡️</div>
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

  // Auto-resize textarea
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
        throw new Error(`HTTP ${response.status}`);
      }

      const data: ChatResponse = await response.json();

      const assistantMessage: Message = {
        id: generateId(),
        role: 'assistant',
        content: data.reply,
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
      {/* Sidebar */}
      <aside className="sidebar">
        <button className="new-chat-btn" onClick={handleNewChat}>
          <span>＋</span>
          <span>New Chat</span>
        </button>
        <div className="sidebar-divider" />
        <div className="sidebar-info">
          <p>
            Aegis Shield detects sensitive information in your messages including emails, phone numbers, monetary values, and secrets.
          </p>
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        {/* Chat Area */}
        <div className="chat-container">
          {messages.length === 0 ? (
            <div className="welcome-screen">
              <div className="welcome-icon">🛡️</div>
              <h1 className="welcome-title">Aegis Shield</h1>
              <p className="welcome-subtitle">
                Paste or type any text to detect sensitive information like emails, phone numbers,
                monetary values, API keys, and secrets.
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

        {/* Input Area */}
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