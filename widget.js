(function() {
  const currentScript = document.currentScript;
  const serverUrl = currentScript && currentScript.getAttribute('data-server') 
    ? currentScript.getAttribute('data-server').replace(/\/$/, '') 
    : window.location.origin;

  const botTitle = currentScript && currentScript.getAttribute('data-title') 
    ? currentScript.getAttribute('data-title') 
    : 'AI Туслах';

  const pageId = currentScript ? (currentScript.getAttribute('data-page-id') || currentScript.getAttribute('data-page')) : null;

  // Session ID
  let sessionId = localStorage.getItem('ai_widget_session_id');
  if (!sessionId) {
    sessionId = 'web_' + Math.random().toString(36).substring(2, 10);
    localStorage.setItem('ai_widget_session_id', sessionId);
  }

  // Handcrafted Organic & Tactile Design Styles
  const style = document.createElement('style');
  style.innerHTML = `
    .ai-chat-btn {
      position: fixed;
      bottom: 24px;
      right: 24px;
      width: 60px;
      height: 60px;
      border-radius: 30px;
      background: radial-gradient(circle at 35% 35%, #2a2b36 0%, #12131a 100%);
      color: #f1f5f9;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      box-shadow: 
        0 4px 14px rgba(0, 0, 0, 0.4),
        0 14px 28px -4px rgba(0, 0, 0, 0.5),
        inset 0 1px 0 rgba(255, 255, 255, 0.2);
      z-index: 999999;
      transition: all 0.28s cubic-bezier(0.34, 1.56, 0.64, 1);
      border: 1px solid rgba(255, 255, 255, 0.12);
      outline: none;
    }
    .ai-chat-btn:hover {
      transform: translateY(-3px) scale(1.05);
      box-shadow: 
        0 8px 20px rgba(0, 0, 0, 0.5),
        0 18px 36px -4px rgba(0, 0, 0, 0.6),
        inset 0 1px 0 rgba(255, 255, 255, 0.3);
      border-color: rgba(255, 255, 255, 0.22);
    }
    .ai-chat-btn:active {
      transform: translateY(1px) scale(0.96);
    }
    .ai-chat-btn svg {
      width: 26px;
      height: 26px;
      fill: #f8fafc;
      transition: transform 0.2s ease;
    }
    .ai-chat-btn:hover svg {
      transform: scale(1.08);
    }
    .ai-chat-window {
      position: fixed;
      bottom: 96px;
      right: 24px;
      width: 390px;
      max-width: calc(100vw - 32px);
      height: 590px;
      max-height: calc(100vh - 120px);
      background: rgba(18, 19, 26, 0.94);
      backdrop-filter: blur(28px) saturate(180%);
      -webkit-backdrop-filter: blur(28px) saturate(180%);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 24px;
      box-shadow: 
        0 2px 4px rgba(0, 0, 0, 0.2),
        0 20px 48px -8px rgba(0, 0, 0, 0.7),
        inset 0 1px 0 rgba(255, 255, 255, 0.15);
      z-index: 999999;
      display: none;
      flex-direction: column;
      overflow: hidden;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", sans-serif;
    }
    .ai-chat-window.open {
      display: flex;
      animation: aiChatOrganicOpen 0.32s cubic-bezier(0.16, 1, 0.3, 1);
    }
    @keyframes aiChatOrganicOpen {
      from { opacity: 0; transform: translateY(18px) scale(0.98); }
      to { opacity: 1; transform: translateY(0) scale(1); }
    }
    .ai-chat-header {
      padding: 16px 18px;
      background: rgba(28, 30, 40, 0.85);
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    }
    .ai-status-pulse {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #34d399;
      box-shadow: 0 0 10px rgba(52, 211, 153, 0.6);
      animation: aiPulse 2.4s infinite ease-in-out;
    }
    @keyframes aiPulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.65; transform: scale(0.88); }
    }
    .ai-chat-body {
      flex: 1;
      padding: 18px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 14px;
      background: radial-gradient(circle at 50% 0%, rgba(30, 32, 45, 0.4) 0%, rgba(13, 14, 20, 0.95) 100%);
    }
    .ai-bubble {
      max-width: 84%;
      padding: 11px 15px;
      font-size: 13.5px;
      line-height: 1.5;
      border-radius: 18px;
      word-break: break-word;
      transition: all 0.2s ease;
    }
    .ai-bubble-user {
      align-self: flex-end;
      background: #3b82f6;
      background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
      color: #ffffff;
      border-bottom-right-radius: 4px;
      box-shadow: 0 3px 10px rgba(37, 99, 235, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.25);
    }
    .ai-bubble-bot {
      align-self: flex-start;
      background: rgba(30, 32, 44, 0.88);
      color: #f1f5f9;
      border-bottom-left-radius: 4px;
      border: 1px solid rgba(255, 255, 255, 0.08);
      box-shadow: 0 3px 12px rgba(0, 0, 0, 0.25), inset 0 1px 0 rgba(255, 255, 255, 0.08);
    }
    .ai-chat-footer {
      padding: 14px;
      background: rgba(24, 26, 36, 0.9);
      display: flex;
      gap: 10px;
      border-top: 1px solid rgba(255, 255, 255, 0.08);
    }
    .ai-chat-input {
      flex: 1;
      background: rgba(14, 15, 22, 0.7);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 14px;
      padding: 11px 15px;
      color: #f8fafc;
      font-size: 13px;
      outline: none;
      transition: border-color 0.2s ease, box-shadow 0.2s ease;
    }
    .ai-chat-input:focus {
      border-color: rgba(96, 165, 250, 0.6);
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.18);
    }
    .ai-chat-send {
      background: #f8fafc;
      border: none;
      color: #0f172a;
      padding: 0 18px;
      border-radius: 14px;
      cursor: pointer;
      font-weight: 700;
      font-size: 13px;
      transition: all 0.2s cubic-bezier(0.34, 1.56, 0.64, 1);
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
    }
    .ai-chat-send:hover {
      transform: translateY(-1px);
      background: #ffffff;
      box-shadow: 0 4px 12px rgba(255, 255, 255, 0.25);
    }
    .ai-chat-send:active {
      transform: translateY(1px) scale(0.96);
    }
    .ai-typing {
      align-self: flex-start;
      font-size: 11.5px;
      color: #94a3b8;
      display: none;
      font-style: italic;
    }
  `;
  document.head.appendChild(style);

  function escapeHtml(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // Widget Elements
  const container = document.createElement('div');
  container.innerHTML = `
    <button class="ai-chat-btn" id="ai-chat-toggle" title="Чат нээх">
      <svg viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H6l-2 2V4h16v12z"/></svg>
    </button>
    <div class="ai-chat-window" id="ai-chat-win">
      <div class="ai-chat-header">
        <div style="display:flex; align-items:center; gap:9px;">
          <div class="ai-status-pulse"></div>
          <div>
            <div style="font-weight:700; font-size:13.5px; color:#ffffff; letter-spacing:-0.2px;">${escapeHtml(botTitle)}</div>
            <div style="font-size:10px; color:#94a3b8;">Шууд хариулахад бэлэн</div>
          </div>
        </div>
        <button id="ai-chat-close" style="background:none; border:none; color:#94a3b8; cursor:pointer; font-size:20px; line-height:1; padding:4px;" title="Хаах">&times;</button>
      </div>
      <div class="ai-chat-body" id="ai-chat-msgs">
        <div class="ai-bubble ai-bubble-bot">Сайн байна уу? Танд өнөөдөр ямар үйлчилгээ, мэдээлэл илүү сонирхолтой байна вэ? Би дуртайяа тусалъя. ✨</div>
        <div class="ai-typing" id="ai-chat-typing">Зөвлөх тунгаан хариулж байна...</div>
      </div>
      <form class="ai-chat-footer" id="ai-chat-form">
        <input class="ai-chat-input" id="ai-chat-txt" placeholder="Асуултаа энд бичнэ үү..." autocomplete="off" />
        <button class="ai-chat-send" type="submit">Илгээх</button>
      </form>
    </div>
  `;
  document.body.appendChild(container);

  const toggleBtn = document.getElementById('ai-chat-toggle');
  const closeBtn = document.getElementById('ai-chat-close');
  const chatWin = document.getElementById('ai-chat-win');
  const chatForm = document.getElementById('ai-chat-form');
  const chatTxt = document.getElementById('ai-chat-txt');
  const msgsDiv = document.getElementById('ai-chat-msgs');
  const typingDiv = document.getElementById('ai-chat-typing');

  toggleBtn.onclick = () => chatWin.classList.toggle('open');
  closeBtn.onclick = () => chatWin.classList.remove('open');

  chatForm.onsubmit = async (e) => {
    e.preventDefault();
    const text = chatTxt.value.trim();
    if (!text) return;

    appendMsg('user', text);
    chatTxt.value = '';
    typingDiv.style.display = 'block';
    msgsDiv.scrollTop = msgsDiv.scrollHeight;

    try {
      const res = await fetch(serverUrl + '/api/chat', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          message: text, 
          sender_id: sessionId,
          page_id: pageId || undefined
        })
      });
      typingDiv.style.display = 'none';
      if (!res.ok) {
        appendMsg('bot', 'Уучлаарай, хүсэлт амжилтгүй боллоо (' + res.status + ').');
        return;
      }
      const data = await res.json();
      if (data.reply) {
        appendMsg('bot', data.reply);
      }
    } catch (err) {
      typingDiv.style.display = 'none';
      appendMsg('bot', 'Уучлаарай, холболт түр саатлаа.');
    }
  };

  function formatSafeBotMessage(str) {
    const escaped = escapeHtml(str);
    return escaped
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+|\/[^\s)]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer" style="color:#60a5fa;text-decoration:underline;font-weight:600;">$1</a>')
      .replace(/\n/g, '<br>');
  }

  function appendMsg(type, text) {
    const bubble = document.createElement('div');
    bubble.className = 'ai-bubble ai-bubble-' + type;
    if (type === 'bot') {
      bubble.innerHTML = formatSafeBotMessage(text);
    } else {
      bubble.innerText = text;
    }
    msgsDiv.insertBefore(bubble, typingDiv);
    msgsDiv.scrollTop = msgsDiv.scrollHeight;
  }
})();
