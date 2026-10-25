/**
 * Zero Trust Messenger — Application Multiplateforme Durcie (Windows, macOS, Android)
 * Conçue pour opérer sur Réseau Mobile / Cellulaire Hostile (4G/5G & Cloudflare Tunnel)
 */

(function () {
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
      httpsUpgradeBanner.textContent = `⚠️ Android exige HTTPS pour autoriser la Caméra et WebCrypto. Appuyez ici pour activer HTTPS (${httpsTarget}) →`;
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

  let myIdentity = null;
  let mySignedQrCache = null;
  let verifiedContacts = [];
  let messagesByContact = {};
  let unreadByContact = {};
  let activeContactId = null;
  let showCipherInspector = true;

  // Fenêtre anti-rejeu basée sur des identifiants de séquence uniques par session
  let outgoingSeqCounter = Math.floor(Date.now() / 1000) * 100;
  const seenPacketIds = new Set();
  let serverClockOffsetSec = 0;
  let currentPublic4gUrl = "https://script-gardening-antibody-fields.trycloudflare.com";

  // État du scanner caméra
  let mediaStream = null;
  let scanInterval = null;
  let facingMode = "environment";
  let lastQrPayloadStr = "";

  // Références DOM
  const appWorkspace = document.getElementById("appWorkspace");
  const myAliasText = document.getElementById("myAliasText");
  const myDeviceIdText = document.getElementById("myDeviceIdText");
  const myFingerprintText = document.getElementById("myFingerprintText");
  const verifiedCountBadge = document.getElementById("verifiedCountBadge");
  const contactsListEl = document.getElementById("contactsList");

  const zeroTrustLockScreen = document.getElementById("zeroTrustLockScreen");
  const activeChatContainer = document.getElementById("activeChatContainer");
  const activeContactName = document.getElementById("activeContactName");
  const activeContactFp = document.getElementById("activeContactFp");
  const chatMessagesArea = document.getElementById("chatMessagesArea");
  const chatComposerForm = document.getElementById("chatComposerForm");
  const chatInput = document.getElementById("chatInput");

  const modalMyQr = document.getElementById("modalMyQr");
  const myQrCanvasContainer = document.getElementById("myQrCanvasContainer");
  const modalMyAlias = document.getElementById("modalMyAlias");
  const modalMyFp = document.getElementById("modalMyFp");

  const modalScanner = document.getElementById("modalScanner");
  const scannerVideo = document.getElementById("scannerVideo");
  const scannerWorkCanvas = document.getElementById("scannerWorkCanvas");
  const scannerStatusMsg = document.getElementById("scannerStatusMsg");
  const btnRequestCameraPerm = document.getElementById("btnRequestCameraPerm");
  const qrFileInput = document.getElementById("qrFileInput");
  const qrNativeCameraInput = document.getElementById("qrNativeCameraInput");

  // =========================================================================
  // 1. INITIALISATION DE L'IDENTITÉ LOCALE
  // =========================================================================
  async function initApp() {
    // Récupération compatible v1 / v2 pour ne jamais perdre l'identité existante du PC
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

    renderIdentityHeader();
    renderContactsList();
    if (verifiedContacts.length > 0 && !activeContactId) {
      selectContact(verifiedContacts[0].id);
    }
    fetchServerStatus();
    startSignedRelayPolling();
  }

  function saveState() {
    localStorage.setItem(STORAGE_KEY_IDENTITY, JSON.stringify(myIdentity));
    localStorage.setItem(STORAGE_KEY_CONTACTS, JSON.stringify(verifiedContacts));
    localStorage.setItem(STORAGE_KEY_MESSAGES, JSON.stringify(messagesByContact));
  }

  function renderIdentityHeader() {
    myAliasText.textContent = myIdentity.alias;
    myDeviceIdText.textContent = myIdentity.deviceId;
    myFingerprintText.textContent = myIdentity.fingerprint;
    document.title = `${myIdentity.alias} — Zero Trust Messenger`;
  }

  // =========================================================================
  // 2. CONTACTS VÉRIFIÉS (KEYRING)
  // =========================================================================
  function renderContactsList() {
    verifiedCountBadge.textContent = String(verifiedContacts.length);
    contactsListEl.innerHTML = "";

    if (verifiedContacts.length === 0) {
      contactsListEl.innerHTML = `
        <div class="empty-contacts-box">
          <div class="empty-contacts-title">Aucun contact vérifié</div>
          <div class="empty-contacts-desc">
            Scannez le QR code d'un contact pour démarrer une conversation chiffrée.
          </div>
        </div>
      `;
      return;
    }

    verifiedContacts.forEach((contact) => {
      const item = document.createElement("div");
      item.className =
        "contact-item" + (contact.id === activeContactId ? " active" : "");
      const initials = (contact.alias || "ZT").slice(0, 2).toUpperCase();
      const unread = unreadByContact[contact.id] || 0;

      item.innerHTML = `
        <div class="contact-avatar">${initials}</div>
        <div class="contact-info">
          <div class="contact-name-row">
            <span class="contact-name">${escapeHtml(contact.alias)}</span>
            ${
              unread > 0
                ? `<span class="unread-badge">${unread}</span>`
                : `<span class="verified-tag">Vérifié</span>`
            }
          </div>
          <div class="contact-fp">${escapeHtml(contact.fingerprint)}</div>
        </div>
      `;

      item.addEventListener("click", () => selectContact(contact.id));
      contactsListEl.appendChild(item);
    });
  }

  function selectContact(contactId) {
    const contact = verifiedContacts.find((c) => c.id === contactId);
    if (!contact) return;

    activeContactId = contact.id;
    unreadByContact[contact.id] = 0;

    zeroTrustLockScreen.style.display = "none";
    activeChatContainer.style.display = "flex";
    activeContactName.textContent = contact.alias;
    activeContactFp.textContent = `Clé secp256r1 : ${contact.fingerprint} | Mailbox : ${contact.mailbox}`;

    appWorkspace.setAttribute("data-mobile-view", "chat");

    renderContactsList();
    renderChatMessages();
  }

  // =========================================================================
  // 3. QR CODE IDENTITY
  // =========================================================================
  async function openMyQrModal() {
    lastQrPayloadStr = await window.ztCrypto.createSignedQrPayload(myIdentity);
    mySignedQrCache = lastQrPayloadStr;
    myQrCanvasContainer.innerHTML = "";
    modalMyAlias.textContent = myIdentity.alias;
    modalMyFp.textContent = myIdentity.fingerprint;

    new QRCode(myQrCanvasContainer, {
      text: lastQrPayloadStr,
      width: 230,
      height: 230,
      colorDark: "#000000",
      colorLight: "#ffffff",
      correctLevel: QRCode.CorrectLevel.L,
    });

    modalMyQr.classList.add("open");
  }

  function downloadMyQrAsPng() {
    const qrCanvas = myQrCanvasContainer.querySelector("canvas");
    const qrImg = myQrCanvasContainer.querySelector("img");

    const exportCanvas = document.createElement("canvas");
    const size = 300;
    const padding = 35;
    exportCanvas.width = size;
    exportCanvas.height = size;
    const ctx = exportCanvas.getContext("2d");
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, size, size);

    const drawSource = qrCanvas || qrImg;
    if (drawSource) {
      ctx.drawImage(
        drawSource,
        padding,
        padding,
        size - padding * 2,
        size - padding * 2
      );
      const dataUrl = exportCanvas.toDataURL("image/png");
      const a = document.createElement("a");
      a.href = dataUrl;
      a.download = `QR_ZeroTrust_${myIdentity.alias}.png`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    }
  }

  // =========================================================================
  // 4. SCANNER DE QR CODE (CAMÉRA ANDROID / WEBCAM / IMPORT IMAGE)
  // =========================================================================
  function openScannerModalAndRequestCamera() {
    if (isInsecureHttpOnLan) {
      window.location.href = `https://${window.location.host}${window.location.pathname}${window.location.search}`;
      return;
    }
    modalScanner.classList.add("open");
    requestCameraPermissionAndStream();
  }

  function closeScannerModal() {
    stopCameraStream();
    modalScanner.classList.remove("open");
  }

  async function requestCameraPermissionAndStream() {
    stopCameraStream();
    btnRequestCameraPerm.style.display = "none";

    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      btnRequestCameraPerm.style.display = "block";
      setScannerStatus(
        "Pour que Chrome Android demande la caméra, ouvrez l'adresse en HTTPS.",
        "error"
      );
      return;
    }

    setScannerStatus(
      "Veuillez autoriser la caméra dans la boîte de dialogue système...",
      ""
    );

    try {
      try {
        mediaStream = await navigator.mediaDevices.getUserMedia({
          video: {
            facingMode: { ideal: facingMode },
            width: { ideal: 640 },
            height: { ideal: 480 },
          },
          audio: false,
        });
      } catch (_) {
        mediaStream = await navigator.mediaDevices.getUserMedia({
          video: true,
          audio: false,
        });
      }

      scannerVideo.srcObject = mediaStream;
      scannerVideo.setAttribute("playsinline", "true");
      await scannerVideo.play();
      btnRequestCameraPerm.style.display = "none";
      setScannerStatus(
        "✓ Caméra active : alignez le QR Code dans le réticule.",
        "success"
      );
      scanInterval = setInterval(scanVideoFrame, 120);
    } catch (err) {
      btnRequestCameraPerm.style.display = "block";
      setScannerStatus(
        "Autorisation caméra refusée ou en attente. Appuyez sur 'Autoriser' ou 'Photo QR'.",
        "error"
      );
    }
  }

  function stopCameraStream() {
    if (scanInterval) {
      clearInterval(scanInterval);
      scanInterval = null;
    }
    if (mediaStream) {
      mediaStream.getTracks().forEach((t) => t.stop());
      mediaStream = null;
    }
    scannerVideo.srcObject = null;
  }

  function scanVideoFrame() {
    if (scannerVideo.readyState !== scannerVideo.HAVE_ENOUGH_DATA) return;
    const w = scannerVideo.videoWidth;
    const h = scannerVideo.videoHeight;
    if (!w || !h) return;

    scannerWorkCanvas.width = w;
    scannerWorkCanvas.height = h;
    const ctx = scannerWorkCanvas.getContext("2d");
    ctx.drawImage(scannerVideo, 0, 0, w, h);

    const imgData = ctx.getImageData(0, 0, w, h);
    const code = window.jsQR(imgData.data, imgData.width, imgData.height, {
      inversionAttempts: "dontInvert",
    });

    if (code && code.data) {
      handleDetectedQrString(code.data);
    }
  }

  function handleQrImageFile(file) {
    if (!file) return;
    setScannerStatus("Analyse cryptographique de l'image QR...", "");

    const reader = new FileReader();
    reader.onload = function (ev) {
      const img = new Image();
      img.onload = function () {
        const maxDim = 1000;
        let drawW = img.width;
        let drawH = img.height;
        if (drawW > maxDim || drawH > maxDim) {
          const ratio = Math.min(maxDim / drawW, maxDim / drawH);
          drawW = Math.round(drawW * ratio);
          drawH = Math.round(drawH * ratio);
        }

        const pad = 40;
        const w = drawW + pad * 2;
        const h = drawH + pad * 2;
        scannerWorkCanvas.width = w;
        scannerWorkCanvas.height = h;
        const ctx = scannerWorkCanvas.getContext("2d");
        ctx.fillStyle = "#ffffff";
        ctx.fillRect(0, 0, w, h);
        ctx.drawImage(img, pad, pad, drawW, drawH);

        const imgData = ctx.getImageData(0, 0, w, h);
        const code = window.jsQR(imgData.data, imgData.width, imgData.height, {
          inversionAttempts: "attemptBoth",
        });

        if (code && code.data) {
          handleDetectedQrString(code.data);
        } else {
          setScannerStatus(
            "Aucun QR Code valide détecté dans cette image.",
            "error"
          );
        }
      };
      img.src = ev.target.result;
    };
    reader.readAsDataURL(file);
  }

  async function handleDetectedQrString(rawQr) {
    const result = await window.ztCrypto.verifyAndParseQrPayload(rawQr);
    if (!result.valid) {
      setScannerStatus(result.error, "error");
      return;
    }

    const contact = result.contact;
    if (contact.id === myIdentity.deviceId) {
      setScannerStatus(
        "Ceci est votre propre QR Code ! Scannez celui d'un autre appareil.",
        "error"
      );
      return;
    }

    registerOrUpdateContact(contact);
    setScannerStatus(
      `✓ Signature ECDSA secp256r1 vérifiée : ${contact.alias} ajouté !`,
      "success"
    );

    await sendEncryptedHandshake(contact);

    setTimeout(() => {
      closeScannerModal();
      selectContact(contact.id);
    }, 400);
  }

  function registerOrUpdateContact(contact) {
    const existingIdx = verifiedContacts.findIndex((c) => c.id === contact.id);
    if (existingIdx >= 0) {
      verifiedContacts[existingIdx] = contact;
    } else {
      verifiedContacts.unshift(contact);
    }
    if (!messagesByContact[contact.id]) {
      messagesByContact[contact.id] = [];
    }
    saveState();
    renderContactsList();
  }

  function setScannerStatus(text, type) {
    scannerStatusMsg.textContent = text;
    scannerStatusMsg.className = "scanner-status-msg" + (type ? ` ${type}` : "");
  }

  // =========================================================================
  // 5. ENVOI & RÉCEPTION SÉCURISÉE AVEC ANTI-REJEU ET AUTO-HANDSHAKE SIGNÉ
  // =========================================================================
  async function sendEncryptedHandshake(targetContact) {
    try {
      const mySignedQr = await window.ztCrypto.createSignedQrPayload(myIdentity);
      mySignedQrCache = mySignedQr;
      outgoingSeqCounter += 1;
      const seq = outgoingSeqCounter;

      const payload = {
        type: "ZERO_TRUST_QR_HANDSHAKE",
        qrPayload: mySignedQr,
        ts: Date.now(),
      };

      const envelope = await window.ztCrypto.encryptMessage(
        myIdentity,
        targetContact,
        seq,
        payload
      );
      await fetch("/api/relay/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_mailbox: targetContact.mailbox,
          packet: {
            sender_id: myIdentity.deviceId,
            envelope,
            ts: Date.now(),
          },
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
      const envelope = await window.ztCrypto.encryptMessage(
        myIdentity,
        targetContact,
        seq,
        payload
      );
      await fetch("/api/relay/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_mailbox: targetContact.mailbox,
          packet: {
            sender_id: myIdentity.deviceId,
            envelope,
            ts: Date.now(),
          },
        }),
      });
    } catch (_) {}
  }

  function showPushNotification(senderName, messageText) {
    if (!("Notification" in window)) return;
    if (Notification.permission === "granted") {
      try {
        const preview = messageText && messageText.length > 30 ? messageText.slice(0, 30) + "..." : messageText;
        new Notification("Nouveau message sécurisé", {
          body: `${senderName}: ${preview}`,
          icon: "/favicon.ico",
          badge: "/favicon.ico",
        });
      } catch (_) {}
    }
  }

  async function sendEncryptedChatMessage(text) {
    const contact = verifiedContacts.find((c) => c.id === activeContactId);
    if (!contact || !text.trim()) return;

    const cleanText = text.trim();
    outgoingSeqCounter += 1;
    const seq = outgoingSeqCounter;

    if (!mySignedQrCache) {
      mySignedQrCache = await window.ztCrypto.createSignedQrPayload(myIdentity);
    }

    const payload = {
      type: "CHAT_MSG",
      msgId: "msg-" + Date.now() + "-" + Math.random().toString(36).slice(2, 6),
      text: cleanText,
      senderId: myIdentity.deviceId,
      senderAlias: myIdentity.alias,
      senderQrPayload: mySignedQrCache,
      ts: Date.now(),
    };

    const envelope = await window.ztCrypto.encryptMessage(
      myIdentity,
      contact,
      seq,
      payload
    );

    const msgEntry = {
      id: payload.msgId,
      senderId: myIdentity.deviceId,
      text: cleanText,
      ts: Date.now(),
      outgoing: true,
      status: "sent",
      seq: seq,
      cipherMeta: {
        eph_x: envelope.eph_x.slice(0, 14) + "...",
        iv: envelope.iv,
        ct: envelope.ct.slice(0, 28) + "...",
        tag: envelope.tag,
        seq: seq,
      },
    };

    if (!messagesByContact[contact.id]) {
      messagesByContact[contact.id] = [];
    }
    messagesByContact[contact.id].push(msgEntry);
    saveState();
    renderChatMessages();

    try {
      await fetch("/api/relay/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target_mailbox: contact.mailbox,
          packet: {
            sender_id: myIdentity.deviceId,
            envelope,
            ts: Date.now(),
          },
        }),
      });
    } catch (_) {}
  }

  function startSignedRelayPolling() {
    const pollFn = async () => {
      if (!myIdentity) return;
      try {
        const ts = Math.floor(Date.now() / 1000) + serverClockOffsetSec;
        const sig = await window.ztCrypto.signPollChallenge(myIdentity, ts);

        const res = await fetch("/api/relay/poll", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-ZT-Protocol": "2.4",
          },
          body: JSON.stringify({
            mailbox: myIdentity.mailbox,
            timestamp: ts,
            signature: sig,
            pub_x: myIdentity.x,
            pub_y: myIdentity.y,
          }),
        });

        const relayBadge = document.getElementById("relayStatusBadge");
        if (!res.ok) {
          if (relayBadge) {
            relayBadge.textContent = `RELAIS : ERREUR (${res.status})`;
          }
          return;
        }
        if (relayBadge) {
          relayBadge.textContent = "RELAIS AVEUGLE : CONNECTÉ";
        }
        const data = await res.json();
        const packets = data.packets || [];
        for (const pkt of packets) {
          await processIncomingEncryptedPacket(pkt);
        }
      } catch (_) {}
    };
    pollFn();
    setInterval(pollFn, 950);
  }

  async function processIncomingEncryptedPacket(packet) {
    try {
      const envelope = packet.envelope;
      if (!envelope) return;

      // Protection Anti-Rejeu par empreinte unique (sender_id + seq + iv)
      const packetUniqueKey = `${packet.sender_id}:${envelope.seq}:${envelope.iv}`;
      if (seenPacketIds.has(packetUniqueKey)) {
        console.warn("[ZeroTrust Anti-Replay] Paquet rejoué bloqué :", packetUniqueKey);
        return;
      }

      let senderContact = verifiedContacts.find(
        (c) => c.id === packet.sender_id
      );

      // Déchiffrement AES-256-GCM avec notre clé privée ECDH secp256r1
      const contactRef = senderContact || {
        id: packet.sender_id,
        x: envelope.eph_x,
        y: envelope.eph_y,
      };
      const decrypted = await window.ztCrypto.decryptMessage(
        myIdentity,
        contactRef,
        envelope
      );
      if (!decrypted) return;

      seenPacketIds.add(packetUniqueKey);

      // Si le paquet contient la preuve QR signée ECDSA de l'émetteur, on vérifie et met à jour le contact
      const qrToVerify = decrypted.qrPayload || decrypted.senderQrPayload;
      if (qrToVerify) {
        const verifyRes = await window.ztCrypto.verifyAndParseQrPayload(
          qrToVerify
        );
        if (verifyRes.valid) {
          senderContact = verifyRes.contact;
          registerOrUpdateContact(senderContact);
          if (!activeContactId) {
            selectContact(senderContact.id);
          }
        }
      }

      if (decrypted.type === "ZERO_TRUST_QR_HANDSHAKE") {
        if (senderContact) {
          selectContact(senderContact.id);
        }
        return;
      }

      if (decrypted.type === "CHAT_READ_RECEIPT" && senderContact) {
        const targetMsgId = decrypted.readMsgId;
        const contactMsgs = messagesByContact[senderContact.id] || [];
        const msg = contactMsgs.find((m) => m.id === targetMsgId || (decrypted.readSeq && m.seq === decrypted.readSeq));
        if (msg && msg.outgoing) {
          msg.status = "read";
          saveState();
          if (activeContactId === senderContact.id) {
            renderChatMessages();
          }
        }
        return;
      }

      if (decrypted.type === "CHAT_MSG" && senderContact) {
        const seq = envelope.seq || 0;
        const incomingMsgId = decrypted.msgId || ("msg-" + Date.now() + "-" + Math.random().toString(36).slice(2, 6));
        const msgEntry = {
          id: incomingMsgId,
          senderId: senderContact.id,
          text: decrypted.text,
          ts: decrypted.ts || Date.now(),
          outgoing: false,
          status: "read",
          seq: seq,
          cipherMeta: {
            eph_x: (envelope.eph_x || "").slice(0, 14) + "...",
            iv: envelope.iv,
            ct: (envelope.ct || "").slice(0, 28) + "...",
            tag: envelope.tag,
            seq: seq,
          },
        };

        if (!messagesByContact[senderContact.id]) {
          messagesByContact[senderContact.id] = [];
        }
        messagesByContact[senderContact.id].push(msgEntry);

        // Envoyer automatiquement un accusé de lecture chiffré E2EE sans fuite
        sendEncryptedReadReceipt(senderContact, incomingMsgId, seq);

        // Déclencher une notification système si l'application est en arrière-plan
        showPushNotification(senderContact.alias, decrypted.text);

        if (!activeContactId) {
          selectContact(senderContact.id);
        } else if (activeContactId === senderContact.id) {
          renderChatMessages();
        } else {
          unreadByContact[senderContact.id] =
            (unreadByContact[senderContact.id] || 0) + 1;
        }

        saveState();
        renderContactsList();
      }
    } catch (err) {
      console.error("[ZeroTrust] Paquet rejeté ou tag GCM invalide :", err);
    }
  }

  function renderChatMessages() {
    chatMessagesArea.innerHTML = "";
    const contact = verifiedContacts.find((c) => c.id === activeContactId);
    if (!contact) return;

    const notice = document.createElement("div");
    notice.className = "system-crypto-notice";
    notice.innerHTML = `
      🔐 <strong>CANAL ZERO TRUST DURCI AVEC ${escapeHtml(
        contact.alias.toUpperCase()
      )}</strong><br/>
      Protection anti-rejeu active. Padding constant 256 octets. Chiffrement matériel ECDH secp256r1 + AES-256-GCM.
    `;
    chatMessagesArea.appendChild(notice);

    const msgs = messagesByContact[contact.id] || [];
    msgs.forEach((m) => {
      const row = document.createElement("div");
      row.className = "msg-row " + (m.outgoing ? "outgoing" : "incoming");

      const timeStr = new Date(m.ts).toLocaleTimeString("fr-FR", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });

      let cipherHtml = "";
      if (showCipherInspector && m.cipherMeta) {
        cipherHtml = `
          <div class="msg-cipher-preview" title="Paquet chiffré avec séquence AAD et padding constant">
            E2EE [#${m.cipherMeta.seq} | EphPK:${escapeHtml(
          m.cipherMeta.eph_x
        )} | IV:${escapeHtml(m.cipherMeta.iv)} | AES-GCM:${escapeHtml(
          m.cipherMeta.ct
        )}]
          </div>
        `;
      }

      let statusIndicator = "";
      if (m.outgoing) {
        if (m.status === "read") {
          statusIndicator = `<span style="color: var(--primary); font-weight: 700; margin-left: 4px;">Vu</span>`;
        } else {
          statusIndicator = `<span style="color: var(--text-sub); margin-left: 4px;">Envoyé</span>`;
        }
      }

      row.innerHTML = `
        <div class="msg-bubble">${escapeHtml(m.text)}</div>
        ${cipherHtml}
        <div class="msg-meta">
          <span>Seq #${m.seq || 0}</span>
          <span>•</span>
          <span>${timeStr}</span>
          <span>•</span>
          <span style="color: #059669; font-weight: 600;">Chiffré AES-256</span>
          ${statusIndicator}
        </div>
      `;
      chatMessagesArea.appendChild(row);
    });

    chatMessagesArea.scrollTop = chatMessagesArea.scrollHeight;
  }

  async function fetchServerStatus() {
    try {
      const res = await fetch("/api/status");
      if (res.ok) {
        const info = await res.json();
        if (info.server_time) {
          serverClockOffsetSec =
            info.server_time - Math.floor(Date.now() / 1000);
        }
        if (info.public_4g_url) {
          currentPublic4gUrl = info.public_4g_url;
        }
        const lanEl = document.getElementById("lanUrlDisplay");
        if (lanEl) {
          if (info.public_4g_url) {
            lanEl.innerHTML = `🌐 <strong>Accès Mobile 4G / 5G :</strong> <a href="${info.public_4g_url}" target="_blank" style="color: var(--cyber-cyan); text-decoration: underline;">${info.public_4g_url}</a>`;
          } else if (info.lan_ip) {
            lanEl.textContent = `Android HTTPS : https://${info.lan_ip}:${info.port}`;
          }
        }
      }
    } catch (_) {}
  }

  function open4gUrlQrModal() {
    const modal4g = document.getElementById("modal4gUrlQr");
    const container = document.getElementById("tunnel4gQrContainer");
    const urlText = document.getElementById("tunnel4gUrlText");
    if (!modal4g || !container) return;

    container.innerHTML = "";
    if (urlText) {
      urlText.textContent = currentPublic4gUrl;
      urlText.href = currentPublic4gUrl;
    }

    new QRCode(container, {
      text: currentPublic4gUrl,
      width: 230,
      height: 230,
      colorDark: "#000000",
      colorLight: "#ffffff",
      correctLevel: QRCode.CorrectLevel.M,
    });

    modal4g.classList.add("open");
  }

  function escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // Événements
  const btnShow4gQr = document.getElementById("btnShow4gQr");
  const btnClose4gQr = document.getElementById("btnClose4gQr");
  if (btnShow4gQr) {
    btnShow4gQr.addEventListener("click", open4gUrlQrModal);
  }
  if (btnClose4gQr) {
    btnClose4gQr.addEventListener("click", () => {
      const modal4g = document.getElementById("modal4gUrlQr");
      if (modal4g) modal4g.classList.remove("open");
    });
  }

  document.getElementById("btnShowMyQr").addEventListener("click", openMyQrModal);
  document.getElementById("btnCloseMyQr").addEventListener("click", () => {
    modalMyQr.classList.remove("open");
  });
  document
    .getElementById("btnDownloadQrPng")
    .addEventListener("click", downloadMyQrAsPng);

  document
    .getElementById("btnOpenScanner")
    .addEventListener("click", openScannerModalAndRequestCamera);
  document
    .getElementById("btnCloseScanner")
    .addEventListener("click", closeScannerModal);

  btnRequestCameraPerm.addEventListener(
    "click",
    requestCameraPermissionAndStream
  );

  document
    .getElementById("btnNativeCameraCapture")
    .addEventListener("click", () => {
      qrNativeCameraInput.value = "";
      qrNativeCameraInput.click();
    });

  qrNativeCameraInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files[0])
      handleQrImageFile(e.target.files[0]);
  });

  document.getElementById("btnImportQrImage").addEventListener("click", () => {
    qrFileInput.value = "";
    qrFileInput.click();
  });

  qrFileInput.addEventListener("change", (e) => {
    if (e.target.files && e.target.files[0])
      handleQrImageFile(e.target.files[0]);
  });

  document.getElementById("btnSwitchCamera").addEventListener("click", () => {
    facingMode = facingMode === "environment" ? "user" : "environment";
    requestCameraPermissionAndStream();
  });

  document.getElementById("btnEditAlias").addEventListener("click", () => {
    const newName = prompt(
      "Entrez votre nouvel alias local :",
      myIdentity.alias
    );
    if (newName && newName.trim()) {
      myIdentity.alias = newName.trim().slice(0, 24);
      saveState();
      renderIdentityHeader();
    }
  });

  document
    .getElementById("btnToggleCipherInspector")
    .addEventListener("click", (e) => {
      showCipherInspector = !showCipherInspector;
      e.target.textContent = `Inspecteur Paquets E2EE : ${
        showCipherInspector ? "ON" : "OFF"
      }`;
      renderChatMessages();
    });

  // Bouton de suppression de discussion
  const btnDeleteConversation = document.getElementById("btnDeleteConversation");
  if (btnDeleteConversation) {
    btnDeleteConversation.addEventListener("click", () => {
      if (!activeContactId) return;
      const contact = verifiedContacts.find((c) => c.id === activeContactId);
      const name = contact ? contact.alias : "ce contact";
      if (confirm(`Voulez-vous supprimer définitivement la discussion avec ${name} et son historique local ?`)) {
        delete messagesByContact[activeContactId];
        saveState();
        renderChatMessages();
      }
    });
  }

  // Bouton d'activation des notifications système
  const btnEnableNotifications = document.getElementById("btnEnableNotifications");
  if (btnEnableNotifications) {
    btnEnableNotifications.addEventListener("click", async () => {
      if (!("Notification" in window)) {
        alert("Les notifications ne sont pas prises en charge par ce navigateur.");
        return;
      }
      const perm = await Notification.requestPermission();
      if (perm === "granted") {
        alert("Notifications activées avec succès !");
      } else {
        alert("Autorisation de notification refusée.");
      }
    });
  }

  document.getElementById("btnMobileBack").addEventListener("click", () => {
    appWorkspace.setAttribute("data-mobile-view", "contacts");
  });

  // Gestion du menu burger mobile (tiroir 3 barres)
  const mobileDrawerBackdrop = document.getElementById("mobileDrawerBackdrop");
  const btnToggleMobileMenu = document.getElementById("btnToggleMobileMenu");
  const btnCloseMobileDrawer = document.getElementById("btnCloseMobileDrawer");
  const btnDrawerShow4gQr = document.getElementById("btnDrawerShow4gQr");
  const btnDrawerOpenSecondDevice = document.getElementById("btnDrawerOpenSecondDevice");

  if (btnToggleMobileMenu && mobileDrawerBackdrop) {
    btnToggleMobileMenu.addEventListener("click", () => {
      mobileDrawerBackdrop.classList.add("open");
    });
  }

  if (btnCloseMobileDrawer && mobileDrawerBackdrop) {
    btnCloseMobileDrawer.addEventListener("click", () => {
      mobileDrawerBackdrop.classList.remove("open");
    });
  }

  if (mobileDrawerBackdrop) {
    mobileDrawerBackdrop.addEventListener("click", (e) => {
      if (e.target === mobileDrawerBackdrop) {
        mobileDrawerBackdrop.classList.remove("open");
      }
    });
  }

  if (btnDrawerShow4gQr) {
    btnDrawerShow4gQr.addEventListener("click", () => {
      if (mobileDrawerBackdrop) mobileDrawerBackdrop.classList.remove("open");
      open4gUrlQrModal();
    });
  }

  if (btnDrawerOpenSecondDevice) {
    btnDrawerOpenSecondDevice.addEventListener("click", () => {
      if (mobileDrawerBackdrop) mobileDrawerBackdrop.classList.remove("open");
      const nextDev = deviceNamespace === "PRIMARY" ? "B" : "C";
      window.open(
        `/?device=${nextDev}`,
        "_blank",
        "width=980,height=720,menubar=no,toolbar=no"
      );
    });
  }

  document
    .getElementById("btnOpenSecondDevice")
    .addEventListener("click", () => {
      const nextDev = deviceNamespace === "PRIMARY" ? "B" : "C";
      window.open(
        `/?device=${nextDev}`,
        "_blank",
        "width=980,height=720,menubar=no,toolbar=no"
      );
    });

  chatComposerForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const text = chatInput.value;
    chatInput.value = "";
    await sendEncryptedChatMessage(text);
  });

  initApp();
})();
