(function() {
  const currentScript = document.currentScript;
  const serverUrl = currentScript && currentScript.getAttribute('data-server') 
    ? currentScript.getAttribute('data-server').replace(/\/$/, '') 
    : window.location.origin;

  const botTitle = currentScript && currentScript.getAttribute('data-title') 
    ? currentScript.getAttribute('data-title') 
    : 'AI Туслах';

  // Session ID
  let sessionId = localStorage.getItem('ai_widget_session_id');
  if (!sessionId) {
    sessionId = 'web_' + Math.random().toString(36).substring(2, 10);
    localStorage.setItem('ai_widget_session_id', sessionId);
  }

  // Styles
  const style = document.createElement('style');
  style.innerHTML = `
    .ai-chat-btn {
      position: fixed;
      bottom: 24px;
      right: 24px;
      width: 60px;
      height: 60px;
      border-radius: 30px;
      background: linear-gradient(135deg, #4f46e5 0%, #3b82f6 100%);
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      box-shadow: 0 10px 25px rgba(79, 70, 229, 0.4);
      z-index: 999999;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      border: none;
      outline: none;
    }
    .ai-chat-btn:hover {
      transform: scale(1.08);
      box-shadow: 0 14px 30px rgba(79, 70, 229, 0.5);
    }
    .ai-chat-btn svg {
      width: 28px;
      height: 28px;
      fill: currentColor;
    }
    .ai-chat-window {
      position: fixed;
      bottom: 96px;
      right: 24px;
      width: 380px;
      max-width: calc(100vw - 32px);
      height: 580px;
      max-height: calc(100vh - 120px);
      background: #0f172a;
      border: 1px solid #1e293b;
      border-radius: 20px;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
      z-index: 999999;
      display: none;
      flex-direction: column;
      overflow: hidden;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }
    .ai-chat-window.open {
      display: flex;
      animation: aiChatSlideUp 0.3s ease-out;
    }
    @keyframes aiChatSlideUp {
      from { opacity: 0; transform: translateY(20px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .ai-chat-header {
      padding: 16px;
      background: #1e293b;
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid #334155;
    }
    .ai-chat-body {
      flex: 1;
      padding: 16px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 12px;
      background: #090d16;
    }
    .ai-bubble {
      max-width: 82%;
      padding: 10px 14px;
      font-size: 13px;
      line-height: 1.45;
      border-radius: 14px;
      word-break: break-word;
    }
    .ai-bubble-user {
      align-self: flex-end;
      background: #4f46e5;
      color: #fff;
      border-bottom-right-radius: 2px;
    }
    .ai-bubble-bot {
      align-self: flex-start;
      background: #1e293b;
      color: #f1f5f9;
      border-bottom-left-radius: 2px;
      border: 1px solid #334155;
    }
    .ai-chat-footer {
      padding: 12px;
      background: #1e293b;
      display: flex;
      gap: 8px;
      border-top: 1px solid #334155;
    }
    .ai-chat-input {
      flex: 1;
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 10px;
      padding: 10px 14px;
      color: #fff;
      font-size: 13px;
      outline: none;
    }
    .ai-chat-send {
      background: #4f46e5;
      border: none;
      color: #fff;
      padding: 0 16px;
      border-radius: 10px;
      cursor: pointer;
      font-weight: 600;
      font-size: 13px;
    }
    .ai-typing {
      align-self: flex-start;
      font-size: 11px;
      color: #94a3b8;
      display: none;
    }
  `;
  document.head.appendChild(style);

  // Widget Elements
  const container = document.createElement('div');
  container.innerHTML = `
    <button class="ai-chat-btn" id="ai-chat-toggle" title="Чат нээх">
      <svg viewBox="0 0 24 24"><path d="M20 2H4c-1.1 0-2 .9-2 2v18l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 14H6l-2 2V4h16v12z"/></svg>
    </button>
    <div class="ai-chat-window" id="ai-chat-win">
      <div class="ai-chat-header">
        <div style="display:flex; align-items:center; gap:8px;">
          <div style="width:10px; height:10px; border-radius:5px; background:#10b981;"></div>
          <span style="font-weight:600; font-size:14px;">${botTitle}</span>
        </div>
        <button id="ai-chat-close" style="background:none; border:none; color:#94a3b8; cursor:pointer; font-size:18px;">&times;</button>
      </div>
      <div class="ai-chat-body" id="ai-chat-msgs">
        <div class="ai-bubble ai-bubble-bot">Сайн байна уу! 👋 Би танд хэрхэн туслах вэ? Бүртгүүлэх эсвэл мэдээлэл асууж болно.</div>
        <div class="ai-typing" id="ai-chat-typing">AI хариулт бэлтгэж байна...</div>
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
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: text, sender_id: sessionId })
      });
      const data = await res.json();
      typingDiv.style.display = 'none';
      if (data.reply) {
        appendMsg('bot', data.reply);
      }
    } catch (err) {
      typingDiv.style.display = 'none';
      appendMsg('bot', 'Уучлаарай, холболт саатлаа.');
    }
  };

  function appendMsg(type, text) {
    const bubble = document.createElement('div');
    bubble.className = 'ai-bubble ai-bubble-' + type;
    bubble.innerText = text;
    msgsDiv.insertBefore(bubble, typingDiv);
    msgsDiv.scrollTop = msgsDiv.scrollHeight;
  }
})();
