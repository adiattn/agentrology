// ==UserScript==
// @name         ChatGPT RL Bridge
// @namespace    chatgpt.com
// @version      3.0
// @match        https://chatgpt.com/*
// @grant        GM_xmlhttpRequest
// @connect 127.0.0.1
// @connect localhost
// ==/UserScript==

(function () {
  const API = "http://127.0.0.1:8080";

  function gmGet(url) {
    return new Promise((resolve, reject) => {
      GM_xmlhttpRequest({
        method: "GET",
        url: url,
        onload: (res) => resolve(JSON.parse(res.responseText)),
        onerror: reject,
      });
    });
  }

  function gmPost(url, data) {
    return new Promise((resolve, reject) => {
      GM_xmlhttpRequest({
        method: "POST",
        url: url,
        headers: { "Content-Type": "application/json" },
        data: JSON.stringify(data),
        onload: (res) => resolve(res.responseText),
        onerror: reject,
      });
    });
  }

  async function fetchPrompt() {
    return gmGet(`${API}/get`);
  }

  async function sendResponse(text) {
    return gmPost(`${API}/response`, { text: text });
  }

  function getAssistantMessages() {
    return document.querySelectorAll('[data-message-author-role="assistant"]');
  }

  function getLastResponse() {
    const msgs = getAssistantMessages();
    if (!msgs.length) return null;

    const lastMsg = msgs[msgs.length - 1];
    return lastMsg.innerText.trim();
  }

  function submit() {
    const btn = document.querySelector("#composer-submit-button");

    if (!btn) {
      console.log("[ERROR] Submit button not found");
      return false;
    }

    if (btn.disabled) {
      console.log(
        "[WAIT] Button disabled (likely empty input or still generating)",
      );
      return false;
    }

    console.log("[LOG] Message sent");
    btn.click();
    return true;
  }

  async function waitForStableResponse(timeout = 20000) {
    const start = Date.now();
    let lastText = "";
    let stableCount = 0;

    while (Date.now() - start < timeout) {
      const text = getLastResponse() || "";

      if (text === lastText && text.length > 0) {
        stableCount++;
      } else {
        stableCount = 0;
      }

      lastText = text;

      // stable for ~1.5s
      if (stableCount >= 3) {
        return text;
      }

      await new Promise((r) => setTimeout(r, 500));
    }

    return lastText; // fallback
  }

  async function typeText(text, delay = 5) {
    const el = document.querySelector('[contenteditable="true"]');

    if (!el) {
      console.log("[ERROR] Input box not found");
      return false;
    }

    el.focus();

    for (const char of text) {
      const event = new InputEvent("input", {
        bubbles: true,
        cancelable: true,
        data: char,
        inputType: "insertText",
      });

      el.textContent += char;
      el.dispatchEvent(event);

      await new Promise((r) => setTimeout(r, delay));
    }

    return true;
  }

  async function setInputText(value) {
    return await typeText(value);
    const el = getInputBox();
    if (!el) return false;

    el.focus();

    const selection = window.getSelection();
    const range = document.createRange();

    range.selectNodeContents(el);
    range.deleteContents();

    const textNode = document.createTextNode(value);
    range.insertNode(textNode);

    selection.removeAllRanges();
    selection.addRange(range);

    return true;
  }

  async function loop() {
    console.log("[BRIDGE] STARTED");
    await new Promise((r) => setTimeout(r, 5 * 1000)); //wait for page to load
    while (true) {
      try {
        const { prompt } = await fetchPrompt();

        // reset
        if (prompt && prompt.trim() === "[RESET]") {
          localStorage.removeItem("oai/apps/conversationDrafts"); // clear draft
          console.log("[RESET] Redirecting to new chat");
          await new Promise((r) => setTimeout(r, 1000));
          window.location.href = "https://chatgpt.com/";
          return;
        }
        if (prompt) {
          console.log("[LOG] Sending:", prompt);

          await setInputText(prompt);
          submit();

          const response = await waitForStableResponse();

          if (response) {
            console.log("[LOG] Received:", response);
            await sendResponse(response);
          }
        }
      } catch (e) {
        console.error(e);
      }

      await new Promise((r) => setTimeout(r, 2000));
    }
  }

  loop();
})();
