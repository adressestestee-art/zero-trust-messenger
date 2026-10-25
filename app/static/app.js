/**
 * Zero Trust Messenger — Moteur Épuré et Silencieux
 * Chiffrement End-to-End P-256 + AES-GCM transparent
 * Interface sobre, ultra simple, zéro emoji.
 */

(function () {
  "use strict";

  const isLanIp =
    window.location.hostname !== "127.0.0.1" &&
    window.location.hostname !== "localhost" &&
    !window.location.hostname.endsWith(".trycloudflare.com");
  const isInsecureHttpOnLan = isLanIp && window.location.protocol === "http:";

  const httpsUpgradeBanner = document.getElementById("httpsUpgradeBanner");
  if (isInsecureHttpOnLan) {
    const httpsTarget = `https://${window.location.host}${window.location.pathname}${window.location.search}`;
    if (httpsUpgradeBanner) {
      httpsUpgradeBanner.style.display = "block";
      httpsUpgradeBanner.addEventListener("click", () => {
        window.location.href = httpsTarget;
      });
    }
    setTimeout(() => {
      window.location.replace(httpsTarget);
    }, 350);
  }

  const urlParams = new URLSearchParams(window.location.search);
  const deviceNamespace = urlParams.get("device") || "PRIMARY";
  const STORAGE_KEY_IDENTITY = `zt_id_v2_${deviceNamespace}`;
  const STORAGE_KEY_CONTACTS = `zt_contacts_v2_${deviceNamespace}`;
  const STORAGE_KEY_MESSAGES = `zt_messages_v2_${deviceNamespace}`;

  // État local
  let myIdentity = null;
  let mySignedQrCache = null;
  let verifiedContacts = [];
  let messagesByContact = {};
  let unreadByContact = {};
  let activeContactId = null;
  let currentView = "dashboard";

  // Anti-rejeu et séquençage
  let outgoingSeqCounter = Math.floor(Date.now() / 1000) * 100;
  const seenPacketIds = new Set();
  let serverClockOffsetSec = 0;
  let remoteServerUrl = window.location.origin;

  // Scanner
  let mediaStream = null;
  let scanInterval = null;

  // Éléments Navigation
  const tabBtnDashboard = document.getElementById("tabBtnDashboard");
  const tabBtnChats = document.getElementById("tabBtnChats");
  const unreadTotalBadge = document.getElementById("unreadTotalBadge");
  const btnToggleSideNav = document.getElementById("btnToggleSideNav");
  const platformIdentifierBadge = document.getElementById("platformIdentifierBadge");
  const btnHeaderMobileLink = document.getElementById("btnHeaderMobileLink");

  const viewDashboard = document.getElementById("viewDashboard");
  const viewChats = document.getElementById("viewChats");
  const chatsLayout = document.querySelector(".chats-layout");

  // Éléments Profil & QR
  const dashAvatar = document.getElementById("dashAvatar");
  const dashMyAlias = document.getElementById("dashMyAlias");
  const btnDashEditAlias = document.getElementById("btnDashEditAlias");
  const dashQrCanvasContainer = document.getElementById("dashQrCanvasContainer");
  const btnDashOpenScanner = document.getElementById("btnDashOpenScanner");
  const btnDashExportQr = document.getElementById("btnDashExportQr");

  const scannerSection = document.getElementById("scannerSection");
  const btnCloseScannerSection = document.getElementById("btnCloseScannerSection");
  const dashScannerVideo = document.getElementById("dashScannerVideo");
  const dashScannerCanvas = document.getElementById("dashScannerCanvas");
  const dashScannerStatus = document.getElementById("dashScannerStatus");
  const btnImportImageQr = document.getElementById("btnImportImageQr");
  const dashFileInput = document.getElementById("dashFileInput");

  // Éléments Conversations
  const chatsSearchInput = document.getElementById("chatsSearchInput");
  const chatsContactsList = document.getElementById("chatsContactsList");
  const btnSwitchToDashboardFromSidebar = document.getElementById("btnSwitchToDashboardFromSidebar");

  const emptyPlatformState = document.getElementById("emptyPlatformState");
  const emptyPlatformIcon = document.getElementById("emptyPlatformIcon");
  const emptyPlatformName = document.getElementById("emptyPlatformName");
  const emptyPlatformGuidance = document.getElementById("emptyPlatformGuidance");

  const activeChatView = document.getElementById("activeChatView");
  const btnChatBackMobile = document.getElementById("btnChatBackMobile");
  const activeChatAvatar = document.getElementById("activeChatAvatar");
  const activeChatPeerName = document.getElementById("activeChatPeerName");
  const btnDeleteActiveChat = document.getElementById("btnDeleteActiveChat");
  const chatMessagesScroll = document.getElementById("chatMessagesScroll");
  const toastNotification = document.getElementById("toastNotification");
  const activeChatComposer = document.getElementById("activeChatComposer");
  const activeChatInput = document.getElementById("activeChatInput");

  // Modale URL
  const modalMobileUrl = document.getElementById("modalMobileUrl");
  const btnCloseModalMobile = document.getElementById("btnCloseModalMobile");
  const serverUrlQrContainer = document.getElementById("serverUrlQrContainer");
  const serverUrlDisplay = document.getElementById("serverUrlDisplay");

  // =========================================================================
  // 1. INITIALISATION & DÉTECTION OS
  // =========================================================================
  async function initApp() {
    detectPlatform();

    const savedId =
      localStorage.getItem(STORAGE_KEY_IDENTITY) ||
      localStorage.getItem(`zt_id_${deviceNamespace}`);
    if (savedId) {
      try {
        myIdentity = JSON.parse(savedId);
      } catch (_) {}
    }

    if (!myIdentity || !myIdentity.d) {
      const defaultName =
        deviceNamespace === "PRIMARY" ? null : `Agent-${deviceNamespace}`;
      myIdentity = await window.ztCrypto.generateIdentity(defaultName);
    }
    localStorage.setItem(STORAGE_KEY_IDENTITY, JSON.stringify(myIdentity));
    mySignedQrCache = await window.ztCrypto.createSignedQrPayload(myIdentity);

    const savedContacts =
      localStorage.getItem(STORAGE_KEY_CONTACTS) ||
      localStorage.getItem(`zt_contacts_${deviceNamespace}`);
    if (savedContacts) {
      try {
        verifiedContacts = JSON.parse(savedContacts);
      } catch (_) {
        verifiedContacts = [];
      }
    }

    const savedMessages =
      localStorage.getItem(STORAGE_KEY_MESSAGES) ||
      localStorage.getItem(`zt_messages_${deviceNamespace}`);
    if (savedMessages) {
      try {
        messagesByContact = JSON.parse(savedMessages);
      } catch (_) {
        messagesByContact = {};
      }
    }

    renderProfileCard();
    renderContactsList();
    updateUnreadTotalBadge();

    switchView("dashboard");
    fetchServerStatus();
    startRelayPolling();
  }

  function detectPlatform() {
    const ua = navigator.userAgent || "";
    let platform = "Web";
    let icon = "WEB";
    let title = "Zero Trust Web";
    let guidance = "Sélectionnez une discussion à gauche pour débuter un échange.";

    if (/iPhone|iPad|iPod/i.test(ua)) {
      platform = "iOS";
      icon = "IOS";
      title = "Zero Trust pour iOS";
      guidance = "Isolation matérielle Secure Enclave active. Choisissez une discussion.";
    } else if (/Macintosh|Mac OS X/i.test(ua)) {
      platform = "macOS";
      icon = "MAC";
      title = "Zero Trust pour macOS";
      guidance = "Session isolée dans la sandbox Apple. Choisissez une discussion.";
    } else if (/Android/i.test(ua)) {
      platform = "Android";
      icon = "AND";
      title = "Zero Trust pour Android";
      guidance = "Clés protégées par le système Android. Choisissez une discussion.";
    } else if (/Windows|Win32|Win64/i.test(ua)) {
      platform = "Windows";
      icon = "WIN";
      title = "Zero Trust pour Windows";
      guidance = "Exécution locale isolée sous Windows. Choisissez une discussion.";
    }

    if (platformIdentifierBadge) platformIdentifierBadge.textContent = platform;
    if (emptyPlatformIcon) emptyPlatformIcon.textContent = icon;
    if (emptyPlatformName) emptyPlatformName.textContent = title;
    if (emptyPlatformGuidance) emptyPlatformGuidance.textContent = guidance;
  }

  function saveState() {
    localStorage.setItem(STORAGE_KEY_IDENTITY, JSON.stringify(myIdentity));
    localStorage.setItem(STORAGE_KEY_CONTACTS, JSON.stringify(verifiedContacts));
    localStorage.setItem(STORAGE_KEY_MESSAGES, JSON.stringify(messagesByContact));
  }

  // =========================================================================
  // 2. NAVIGATION ENTRE ONGLETS
  // =========================================================================
  function switchView(viewName) {
    currentView = viewName;
    document.body.setAttribute("data-view", viewName);

    if (viewName === "dashboard") {
      tabBtnDashboard.classList.add("active");
      tabBtnChats.classList.remove("active");
      viewDashboard.classList.add("active");
      viewChats.classList.remove("active");
      stopCameraScanner();
    } else {
      tabBtnDashboard.classList.remove("active");
      tabBtnChats.classList.add("active");
      viewDashboard.classList.remove("active");
      viewChats.classList.add("active");
      if (!activeContactId && chatsLayout) {
        chatsLayout.setAttribute("data-chat-view", "list");
      }
    }
  }

  tabBtnDashboard.addEventListener("click", () => switchView("dashboard"));
  tabBtnChats.addEventListener("click", () => switchView("chats"));
  btnSwitchToDashboardFromSidebar.addEventListener("click", () => switchView("dashboard"));

  btnToggleSideNav.addEventListener("click", () => {
    if (currentView === "dashboard") {
      switchView("chats");
      if (chatsLayout) chatsLayout.setAttribute("data-chat-view", "list");
    } else {
      if (chatsLayout) {
        const isRoom = chatsLayout.getAttribute("data-chat-view") === "room";
        chatsLayout.setAttribute("data-chat-view", isRoom ? "list" : "room");
      }
    }
  });

  if (btnChatBackMobile) {
    btnChatBackMobile.addEventListener("click", () => {
      if (chatsLayout) chatsLayout.setAttribute("data-chat-view", "list");
    });
  }

  // =========================================================================
  // 3. PROFIL & QR CODE ÉPURÉ
  // =========================================================================
  async function renderProfileCard() {
    if (!myIdentity) return;
    const initials = (myIdentity.alias || "ZT").slice(0, 2).toUpperCase();
    if (dashAvatar) dashAvatar.textContent = initials;
    if (dashMyAlias) dashMyAlias.textContent = myIdentity.alias;

    if (dashQrCanvasContainer) {
      dashQrCanvasContainer.innerHTML = "";
      mySignedQrCache = await window.ztCrypto.createSignedQrPayload(myIdentity);
      new QRCode(dashQrCanvasContainer, {
        text: mySignedQrCache,
        width: 190,
        height: 190,
        colorDark: "#000000",
        colorLight: "#ffffff",
        correctLevel: QRCode.CorrectLevel.L,
      });
    }
  }

  if (btnDashEditAlias) {
    btnDashEditAlias.addEventListener("click", () => {
      const nouveau = prompt("Modifier votre nom d'utilisateur :", myIdentity.alias);
      if (nouveau && nouveau.trim()) {
        myIdentity.alias = nouveau.trim().slice(0, 20);
        saveState();
        renderProfileCard();
      }
    });
  }

  if (btnDashExportQr) {
    btnDashExportQr.addEventListener("click", () => {
      const qrCanvas = dashQrCanvasContainer.querySelector("canvas");
      const qrImg = dashQrCanvasContainer.querySelector("img");
      const exportCanvas = document.createElement("canvas");
      const size = 300;
      exportCanvas.width = size;
      exportCanvas.height = size;
      const ctx = exportCanvas.getContext("2d");
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, size, size);

      const src = qrCanvas || qrImg;
      if (src) {
        ctx.drawImage(src, 30, 30, 240, 240);
        const a = document.createElement("a");
        a.href = exportCanvas.toDataURL("image/png");
        a.download = `ZT_${myIdentity.alias}.png`;
        a.click();
      }
    });
  }

  // =========================================================================
  // 4. SCANNER CAMERA & IMPORT SIMPLE
  // =========================================================================
  if (btnDashOpenScanner) {
    btnDashOpenScanner.addEventListener("click", () => {
      scannerSection.style.display = "flex";
      startCameraScanner();
      scannerSection.scrollIntoView({ behavior: "smooth" });
    });
  }

  if (btnCloseScannerSection) {
    btnCloseScannerSection.addEventListener("click", () => {
      stopCameraScanner();
      scannerSection.style.display = "none";
    });
  }

  async function startCameraScanner() {
    stopCameraScanner();
    dashScannerStatus.textContent = "Initialisation de la caméra...";
    dashScannerStatus.style.color = "var(--text-secondary)";

    try {
      mediaStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: "environment" } },
        audio: false,
      });
      dashScannerVideo.srcObject = mediaStream;
      await dashScannerVideo.play();
      dashScannerStatus.textContent = "Caméra active : visez le QR code";
      scanInterval = setInterval(scanVideoFrame, 130);
    } catch (_) {
      dashScannerStatus.textContent = "Caméra indisponible ou refusée.";
      dashScannerStatus.style.color = "#f87171";
    }
  }

  function stopCameraScanner() {
    if (scanInterval) {
      clearInterval(scanInterval);
      scanInterval = null;
    }
    if (mediaStream) {
      mediaStream.getTracks().forEach((t) => t.stop());
      mediaStream = null;
    }
    if (dashScannerVideo) dashScannerVideo.srcObject = null;
  }

  function scanVideoFrame() {
    if (!dashScannerVideo || dashScannerVideo.readyState !== dashScannerVideo.HAVE_ENOUGH_DATA) return;
    const w = dashScannerVideo.videoWidth;
    const h = dashScannerVideo.videoHeight;
    if (!w || !h || !dashScannerCanvas) return;

    dashScannerCanvas.width = w;
    dashScannerCanvas.height = h;
    const ctx = dashScannerCanvas.getContext("2d");
    ctx.drawImage(dashScannerVideo, 0, 0, w, h);

    const imgData = ctx.getImageData(0, 0, w, h);
    if (!window.jsQR) return;
    const code = window.jsQR(imgData.data, imgData.width, imgData.height, { inversionAttempts: "dontInvert" });
    if (code && code.data) {
      handleScannedPayload(code.data);
    }
  }

  if (btnImportImageQr && dashFileInput) {
    btnImportImageQr.addEventListener("click", () => {
      dashFileInput.value = "";
      dashFileInput.click();
    });
    dashFileInput.addEventListener("change", (e) => {
      if (e.target.files && e.target.files[0]) {
        handleQrFile(e.target.files[0]);
      }
    });
  }

  function handleQrFile(file) {
    const reader = new FileReader();
    reader.onload = function (ev) {
      const img = new Image();
      img.onload = function () {
        dashScannerCanvas.width = img.width;
        dashScannerCanvas.height = img.height;
        const ctx = dashScannerCanvas.getContext("2d");
        ctx.drawImage(img, 0, 0);
        const imgData = ctx.getImageData(0, 0, img.width, img.height);
        if (window.jsQR) {
          const code = window.jsQR(imgData.data, imgData.width, imgData.height, { inversionAttempts: "attemptBoth" });
          if (code && code.data) {
            handleScannedPayload(code.data);
          } else {
            alert("Aucun QR code trouvé dans cette photo.");
          }
        }
      };
      img.src = ev.target.result;
    };
    reader.readAsDataURL(file);
  }

  async function handleScannedPayload(rawQr) {
    const res = await window.ztCrypto.verifyAndParseQrPayload(rawQr);
    if (!res.valid) {
      dashScannerStatus.textContent = "QR code invalide.";
      return;
    }
    const contact = res.contact;
    if (contact.id === myIdentity.deviceId) {
      dashScannerStatus.textContent = "Ceci est votre propre code.";
      return;
    }

    registerOrUpdateContact(contact);
    await sendEncryptedHandshake(contact);

    stopCameraScanner();
    scannerSection.style.display = "none";
    switchView("chats");
    selectContact(contact.id);
  }

  // =========================================================================
  // 5. GESTION DES CONTACTS & LISTE
  // =========================================================================
  let searchQuery = "";
  if (chatsSearchInput) {
    chatsSearchInput.addEventListener("input", (e) => {
      searchQuery = e.target.value.toLowerCase().trim();
      renderContactsList();
    });
  }

  function renderContactsList() {
    if (!chatsContactsList) return;
    chatsContactsList.innerHTML = "";

    const filtered = verifiedContacts.filter((c) =>
      c.alias.toLowerCase().includes(searchQuery)
    );

    if (filtered.length === 0) {
      const p = document.createElement("div");
      p.style.padding = "20px 10px";
      p.style.textAlign = "center";
      p.style.color = "var(--text-muted)";
      p.style.fontSize = "12px";
      p.textContent = searchQuery ? "Aucun contact." : "Aucune discussion.";
      chatsContactsList.appendChild(p);
      return;
    }

    filtered.forEach((contact) => {
      const row = document.createElement("div");
      row.className = "contact-row" + (contact.id === activeContactId ? " active" : "");
      const initials = (contact.alias || "ZT").slice(0, 2).toUpperCase();
      const unread = unreadByContact[contact.id] || 0;
      const msgs = messagesByContact[contact.id] || [];
      const lastMsg = msgs.length > 0 ? msgs[msgs.length - 1].text : "Discussion sécurisée";

      row.innerHTML = `
        <div class="contact-avatar">${initials}</div>
        <div class="contact-meta">
          <div class="contact-name-row">
            <span class="contact-name">${escapeHtml(contact.alias)}</span>
            ${unread > 0 ? `<span class="unread-count">${unread}</span>` : ""}
          </div>
          <div class="contact-sub">${escapeHtml(lastMsg)}</div>
        </div>
      `;

      row.addEventListener("click", () => {
        selectContact(contact.id);
        if (chatsLayout) chatsLayout.setAttribute("data-chat-view", "room");
      });

      chatsContactsList.appendChild(row);
    });
  }

  function selectContact(contactId) {
    const contact = verifiedContacts.find((c) => c.id === contactId);
    if (!contact) return;

    activeContactId = contact.id;
    unreadByContact[contact.id] = 0;
    updateUnreadTotalBadge();

    if (emptyPlatformState) emptyPlatformState.style.display = "none";
    if (activeChatView) activeChatView.style.display = "flex";

    const initials = (contact.alias || "ZT").slice(0, 2).toUpperCase();
    if (activeChatAvatar) activeChatAvatar.textContent = initials;
    if (activeChatPeerName) activeChatPeerName.textContent = contact.alias;

    if (chatsLayout) chatsLayout.setAttribute("data-chat-view", "room");

    renderContactsList();
    renderChatMessages();
  }

  function updateUnreadTotalBadge() {
    let total = 0;
    Object.keys(unreadByContact).forEach((k) => {
      total += unreadByContact[k] || 0;
    });
    if (unreadTotalBadge) {
      if (total > 0) {
        unreadTotalBadge.style.display = "inline-block";
        unreadTotalBadge.textContent = String(total);
      } else {
        unreadTotalBadge.style.display = "none";
      }
    }
  }

  function registerOrUpdateContact(contact) {
    const idx = verifiedContacts.findIndex((c) => c.id === contact.id);
    if (idx >= 0) {
      verifiedContacts[idx] = contact;
    } else {
      verifiedContacts.unshift(contact);
    }
    if (!messagesByContact[contact.id]) {
      messagesByContact[contact.id] = [];
    }
    saveState();
    renderContactsList();
  }

  // =========================================================================
  // 6. MESSAGERIE & ENVOI SÉCURISÉ (SILENCIEUX)
  // =========================================================================
  async function sendEncryptedHandshake(targetContact) {
    try {
      outgoingSeqCounter += 1;
      const seq = outgoingSeqCounter;
      const payload = {
        type: "ZERO_TRUST_QR_HANDSHAKE",
        qrPayload: mySignedQrCache || (await window.ztCrypto.createSignedQrPayload(myIdentity)),
        ts: Date.now(),
      };
      const envelope = await window.ztCrypto.encryptMessage(myIdentity, targetContact, seq, payload);
      await fetch("/api/relay/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_mailbox: targetContact.mailbox,
          packet: { sender_id: myIdentity.deviceId, envelope, ts: Date.now() },
        }),
      });
    } catch (_) {}
  }

  async function sendEncryptedReadReceipt(targetContact, readMsgId, readSeq) {
    try {
      outgoingSeqCounter += 1;
      const seq = outgoingSeqCounter;
      const payload = {
        type: "CHAT_READ_RECEIPT",
        readMsgId: readMsgId,
        readSeq: readSeq,
        senderId: myIdentity.deviceId,
        ts: Date.now(),
      };
      const envelope = await window.ztCrypto.encryptMessage(myIdentity, targetContact, seq, payload);
      await fetch("/api/relay/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_mailbox: targetContact.mailbox,
          packet: { sender_id: myIdentity.deviceId, envelope, ts: Date.now() },
        }),
      });
    } catch (_) {}
  }

  async function sendEncryptedChatMessage(text) {
    const contact = verifiedContacts.find((c) => c.id === activeContactId);
    if (!contact || !text.trim()) return;

    const cleanText = text.trim();
    outgoingSeqCounter += 1;
    const seq = outgoingSeqCounter;

    const payload = {
      type: "CHAT_MSG",
      msgId: "msg-" + Date.now() + "-" + Math.random().toString(36).slice(2, 6),
      text: cleanText,
      senderId: myIdentity.deviceId,
      senderAlias: myIdentity.alias,
      senderQrPayload: mySignedQrCache,
      ts: Date.now(),
    };

    const envelope = await window.ztCrypto.encryptMessage(myIdentity, contact, seq, payload);

    const msgEntry = {
      id: payload.msgId,
      senderId: myIdentity.deviceId,
      text: cleanText,
      ts: Date.now(),
      outgoing: true,
      status: "sent",
      seq: seq,
    };

    if (!messagesByContact[contact.id]) {
      messagesByContact[contact.id] = [];
    }
    messagesByContact[contact.id].push(msgEntry);
    saveState();
    renderChatMessages();
    renderContactsList();

    try {
      await fetch("/api/relay/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_mailbox: contact.mailbox,
          packet: { sender_id: myIdentity.deviceId, envelope, ts: Date.now() },
        }),
      });
    } catch (_) {}
  }

  if (activeChatComposer) {
    activeChatComposer.addEventListener("submit", async (e) => {
      e.preventDefault();
      if (!activeChatInput) return;
      const text = activeChatInput.value;
      activeChatInput.value = "";
      await sendEncryptedChatMessage(text);
    });
  }

  // =========================================================================
  // 7. POLLING DU RELAIS CLOUD
  // =========================================================================
  function startRelayPolling() {
    const pollFn = async () => {
      if (!myIdentity) return;
      try {
        const ts = Math.floor(Date.now() / 1000) + serverClockOffsetSec;
        const sig = await window.ztCrypto.signPollChallenge(myIdentity, ts);

        const res = await fetch("/api/relay/poll", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-ZT-Protocol": "3.1",
          },
          body: JSON.stringify({
            mailbox: myIdentity.mailbox,
            timestamp: ts,
            signature: sig,
            pub_x: myIdentity.x,
            pub_y: myIdentity.y,
          }),
        });

        if (res.ok) {
          const data = await res.json();
          const packets = data.packets || [];
          for (const pkt of packets) {
            await processIncomingPacket(pkt);
          }
        }
      } catch (_) {}
    };

    pollFn();
    setInterval(pollFn, 950);
  }

  async function processIncomingPacket(packet) {
    try {
      const envelope = packet.envelope;
      if (!envelope) return;

      const packetKey = `${packet.sender_id}:${envelope.seq}:${envelope.iv}`;
      if (seenPacketIds.has(packetKey)) return;

      let senderContact = verifiedContacts.find((c) => c.id === packet.sender_id);
      const contactRef = senderContact || { id: packet.sender_id, x: envelope.eph_x, y: envelope.eph_y };

      const decrypted = await window.ztCrypto.decryptMessage(myIdentity, contactRef, envelope);
      if (!decrypted) return;

      seenPacketIds.add(packetKey);

      const qrPayload = decrypted.qrPayload || decrypted.senderQrPayload;
      if (qrPayload) {
        const verifyRes = await window.ztCrypto.verifyAndParseQrPayload(qrPayload);
        if (verifyRes.valid) {
          senderContact = verifyRes.contact;
          registerOrUpdateContact(senderContact);
          if (!activeContactId) selectContact(senderContact.id);
        }
      }

      if (decrypted.type === "ZERO_TRUST_QR_HANDSHAKE") {
        if (senderContact) selectContact(senderContact.id);
        return;
      }

      if (decrypted.type === "CHAT_READ_RECEIPT" && senderContact) {
        const msgs = messagesByContact[senderContact.id] || [];
        const msg = msgs.find((m) => m.id === decrypted.readMsgId || (decrypted.readSeq && m.seq === decrypted.readSeq));
        if (msg && msg.outgoing) {
          msg.status = "read";
          saveState();
          if (activeContactId === senderContact.id) renderChatMessages();
        }
        return;
      }

      if (decrypted.type === "CHAT_MSG" && senderContact) {
        const seq = envelope.seq || 0;
        const msgId = decrypted.msgId || ("msg-" + Date.now());

        const msgEntry = {
          id: msgId,
          senderId: senderContact.id,
          text: decrypted.text,
          ts: decrypted.ts || Date.now(),
          outgoing: false,
          status: "read",
          seq: seq,
        };

        if (!messagesByContact[senderContact.id]) {
          messagesByContact[senderContact.id] = [];
        }
        messagesByContact[senderContact.id].push(msgEntry);

        sendEncryptedReadReceipt(senderContact, msgId, seq);

        if (!activeContactId) {
          selectContact(senderContact.id);
        } else if (activeContactId === senderContact.id) {
          renderChatMessages();
        } else {
          unreadByContact[senderContact.id] = (unreadByContact[senderContact.id] || 0) + 1;
          updateUnreadTotalBadge();
        }

        saveState();
        renderContactsList();
      }
    } catch (_) {}
  }

  // =========================================================================
  // 8. RENDU DES MESSAGES
  // =========================================================================
  function renderChatMessages() {
    if (!chatMessagesScroll) return;
    chatMessagesScroll.innerHTML = "";

    const contact = verifiedContacts.find((c) => c.id === activeContactId);
    if (!contact) return;

    const msgs = messagesByContact[contact.id] || [];

    msgs.forEach((m) => {
      const row = document.createElement("div");
      row.className = "chat-bubble-row " + (m.outgoing ? "outgoing" : "incoming");

      const timeStr = new Date(m.ts).toLocaleTimeString("fr-FR", {
        hour: "2-digit",
        minute: "2-digit",
      });

      const statusTag = m.outgoing
        ? m.status === "read"
          ? `<span class="status-vu">Vu</span>`
          : `<span>Envoyé</span>`
        : "";

      row.innerHTML = `
        <div class="chat-bubble">${escapeHtml(m.text)}</div>
        <div class="bubble-meta">
          <span>${timeStr}</span>
          ${statusTag}
        </div>
      `;

      const bubble = row.querySelector(".chat-bubble");
      if (bubble) {
        bubble.addEventListener("click", () => {
          if (navigator.clipboard) {
            navigator.clipboard.writeText(m.text).then(() => showToast("Copié")).catch(() => {});
          }
        });
      }

      chatMessagesScroll.appendChild(row);
    });

    chatMessagesScroll.scrollTop = chatMessagesScroll.scrollHeight;
  }

  function showToast(text) {
    if (!toastNotification) return;
    toastNotification.textContent = text;
    toastNotification.classList.add("show");
    setTimeout(() => {
      toastNotification.classList.remove("show");
    }, 1200);
  }

  if (btnDeleteActiveChat) {
    btnDeleteActiveChat.addEventListener("click", () => {
      if (!activeContactId) return;
      if (confirm("Supprimer l'historique de cette discussion ?")) {
        delete messagesByContact[activeContactId];
        saveState();
        renderChatMessages();
        renderContactsList();
      }
    });
  }

  // =========================================================================
  // 9. SERVEUR & PARTAGE DE LIEN
  // =========================================================================
  async function fetchServerStatus() {
    try {
      const res = await fetch("/api/status");
      if (res.ok) {
        const info = await res.json();
        if (info.server_time) serverClockOffsetSec = info.server_time - Math.floor(Date.now() / 1000);
        if (info.public_4g_url) remoteServerUrl = info.public_4g_url;
      }
    } catch (_) {}
  }

  if (btnHeaderMobileLink) {
    btnHeaderMobileLink.addEventListener("click", () => {
      if (!modalMobileUrl || !serverUrlQrContainer) return;
      serverUrlQrContainer.innerHTML = "";
      const targetUrl = remoteServerUrl || window.location.origin;
      if (serverUrlDisplay) {
        serverUrlDisplay.textContent = targetUrl;
        serverUrlDisplay.href = targetUrl;
      }
      new QRCode(serverUrlQrContainer, {
        text: targetUrl,
        width: 180,
        height: 180,
        colorDark: "#000000",
        colorLight: "#ffffff",
        correctLevel: QRCode.CorrectLevel.M,
      });
      modalMobileUrl.classList.add("open");
    });
  }

  if (btnCloseModalMobile) {
    btnCloseModalMobile.addEventListener("click", () => {
      if (modalMobileUrl) modalMobileUrl.classList.remove("open");
    });
  }

  function escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  initApp();
})();
