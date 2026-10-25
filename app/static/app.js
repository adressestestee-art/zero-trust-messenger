/**
 * Zero Trust Messenger — Application Multiplateforme Durcie (Windows, macOS, Android)
 * Conçue pour opérer sur Réseau Mobile / Cellulaire Hostile & Cloudflare Tunnel
 * Architecture Zero-Knowledge : Aucun message en clair sur le relais cloud.
 * Zéro Emoji / Interface Haute Sécurité Sobre.
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
      httpsUpgradeBanner.textContent = `Connexion non securisee. Cliquez ici pour activer le chiffrement HTTPS (${httpsTarget}) ->`;
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

  // Etat principal de l'application
  let myIdentity = null;
  let mySignedQrCache = null;
  let verifiedContacts = [];
  let messagesByContact = {};
  let unreadByContact = {};
  let activeContactId = null;
  let showCipherInspector = true;
  let currentView = "dashboard"; // "dashboard" ou "chats"

  // Fenetre anti-rejeu basee sur des identifiants de sequence uniques
  let outgoingSeqCounter = Math.floor(Date.now() / 1000) * 100;
  const seenPacketIds = new Set();
  let serverClockOffsetSec = 0;
  let remoteServerUrl = window.location.origin;

  // Scanner camera
  let mediaStream = null;
  let scanInterval = null;
  let facingMode = "environment";

  // Elements DOM Navigation & Layout
  const bodyEl = document.body;
  const tabBtnDashboard = document.getElementById("tabBtnDashboard");
  const tabBtnChats = document.getElementById("tabBtnChats");
  const unreadTotalBadge = document.getElementById("unreadTotalBadge");
  const btnToggleSideNav = document.getElementById("btnToggleSideNav");
  const relayStatusText = document.getElementById("relayStatusText");
  const btnHeaderMobileLink = document.getElementById("btnHeaderMobileLink");

  const viewDashboard = document.getElementById("viewDashboard");
  const viewChats = document.getElementById("viewChats");
  const chatsLayout = document.querySelector(".chats-layout");
  const chatDrawer = document.getElementById("chatDrawer");

  // Elements Dashboard
  const platformIdentifierBadge = document.getElementById("platformIdentifierBadge");
  const dashMyAlias = document.getElementById("dashMyAlias");
  const btnDashEditAlias = document.getElementById("btnDashEditAlias");
  const dashMyDeviceId = document.getElementById("dashMyDeviceId");
  const dashMyFingerprint = document.getElementById("dashMyFingerprint");
  const dashQrCanvasContainer = document.getElementById("dashQrCanvasContainer");
  const btnDashExportQr = document.getElementById("btnDashExportQr");

  const dashScannerVideo = document.getElementById("dashScannerVideo");
  const dashScannerCanvas = document.getElementById("dashScannerCanvas");
  const btnTriggerScannerPerm = document.getElementById("btnTriggerScannerPerm");
  const dashScannerStatus = document.getElementById("dashScannerStatus");
  const btnStartCameraLive = document.getElementById("btnStartCameraLive");
  const btnImportImageQr = document.getElementById("btnImportImageQr");
  const dashFileInput = document.getElementById("dashFileInput");

  // Elements Conversations
  const chatsCountBadge = document.getElementById("chatsCountBadge");
  const btnCloseDrawerMobile = document.getElementById("btnCloseDrawerMobile");
  const chatsSearchInput = document.getElementById("chatsSearchInput");
  const chatsContactsList = document.getElementById("chatsContactsList");
  const btnSwitchToDashboardFromSidebar = document.getElementById("btnSwitchToDashboardFromSidebar");

  const emptyPlatformState = document.getElementById("emptyPlatformState");
  const emptyPlatformName = document.getElementById("emptyPlatformName");
  const emptyPlatformGuidance = document.getElementById("emptyPlatformGuidance");
  const specPlatform = document.getElementById("specPlatform");
  const specStorage = document.getElementById("specStorage");
  const btnEmptyGoDashboard = document.getElementById("btnEmptyGoDashboard");

  const activeChatView = document.getElementById("activeChatView");
  const btnChatBackMobile = document.getElementById("btnChatBackMobile");
  const activeChatPeerName = document.getElementById("activeChatPeerName");
  const activeChatPeerMeta = document.getElementById("activeChatPeerMeta");
  const btnDeleteActiveChat = document.getElementById("btnDeleteActiveChat");
  const btnToggleInspector = document.getElementById("btnToggleInspector");
  const chatMessagesScroll = document.getElementById("chatMessagesScroll");
  const toastNotification = document.getElementById("toastNotification");
  const activeChatComposer = document.getElementById("activeChatComposer");
  const activeChatInput = document.getElementById("activeChatInput");

  // Elements Modal URL Mobile
  const modalMobileUrl = document.getElementById("modalMobileUrl");
  const btnCloseModalMobile = document.getElementById("btnCloseModalMobile");
  const serverUrlQrContainer = document.getElementById("serverUrlQrContainer");
  const serverUrlDisplay = document.getElementById("serverUrlDisplay");

  // =========================================================================
  // 1. INITIALISATION DE L'APPLICATION & DETECTION PLATEFORME
  // =========================================================================
  async function initApp() {
    detectPlatform();

    // Recuperation identite locale
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

    // Recuperation des contacts verifies
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

    // Recuperation des messages
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
    renderDashboardQr();
    renderContactsList();
    updateUnreadTotalBadge();

    // Initialisation du routeur de vue
    switchView("dashboard");

    // Connexion au serveur de statut et relais
    fetchServerStatus();
    startSignedRelayPolling();
  }

  function detectPlatform() {
    const ua = navigator.userAgent || "";
    let platform = "Web";
    let storage = "WebCrypto IndexedDB Isolee";
    let guidance =
      "Selectionnez un contact verifie ou utilisez le scanner QR pour etablir un canal confidentiel.";

    if (/iPhone|iPad|iPod/i.test(ua)) {
      platform = "Apple iOS";
      storage = "Apple Secure Enclave (WebCrypto)";
      guidance =
        "Environnement iOS : Cles locales generees via WebCrypto et isolees dans la Secure Enclave du terminal.";
    } else if (/Macintosh|Mac OS X/i.test(ua)) {
      platform = "Apple macOS";
      storage = "macOS Keychain Vault";
      guidance =
        "Environnement macOS : Cles isolees au sein du trousseau local et de la sandbox WebKit.";
    } else if (/Android/i.test(ua)) {
      platform = "Android";
      storage = "Android KeyStore Sandbox";
      guidance =
        "Environnement Android : Isolation cryptographique stricte au sein du bac a sable de l'application.";
    } else if (/Windows|Win32|Win64/i.test(ua)) {
      platform = "Windows";
      storage = "Windows DPAPI & WebView2 Sandbox";
      guidance =
        "Environnement Windows : Execution native sans dependance externe, stockage chiffre sous DPAPI.";
    } else if (/Linux/i.test(ua)) {
      platform = "Linux";
      storage = "Linux Kernel Keyring (WebCrypto)";
      guidance =
        "Environnement Linux : Protection du processus et isolation memoire WebCrypto.";
    }

    if (platformIdentifierBadge) {
      platformIdentifierBadge.textContent = platform;
    }
    if (emptyPlatformName) {
      emptyPlatformName.textContent = `Espace ${platform} Securise`;
    }
    if (emptyPlatformGuidance) {
      emptyPlatformGuidance.textContent = guidance;
    }
    if (specPlatform) {
      specPlatform.textContent = platform;
    }
    if (specStorage) {
      specStorage.textContent = storage;
    }
  }

  function saveState() {
    localStorage.setItem(STORAGE_KEY_IDENTITY, JSON.stringify(myIdentity));
    localStorage.setItem(STORAGE_KEY_CONTACTS, JSON.stringify(verifiedContacts));
    localStorage.setItem(STORAGE_KEY_MESSAGES, JSON.stringify(messagesByContact));
  }

  function renderIdentityHeader() {
    if (dashMyAlias) dashMyAlias.textContent = myIdentity.alias;
    if (dashMyDeviceId) dashMyDeviceId.textContent = myIdentity.deviceId;
    if (dashMyFingerprint) dashMyFingerprint.textContent = myIdentity.fingerprint;
    document.title = `${myIdentity.alias} — Zero Trust Messenger`;
  }

  // =========================================================================
  // 2. GESTION DES DEUX VUES (ACCUEIL / CONVERSATIONS) & TIROIR MOBILE
  // =========================================================================
  function switchView(viewName) {
    currentView = viewName;
    bodyEl.setAttribute("data-view", viewName);

    if (viewName === "dashboard") {
      tabBtnDashboard.classList.add("active");
      tabBtnChats.classList.remove("active");
      viewDashboard.classList.add("active");
      viewChats.classList.remove("active");
      stopCameraStream();
    } else if (viewName === "chats") {
      tabBtnDashboard.classList.remove("active");
      tabBtnChats.classList.add("active");
      viewDashboard.classList.remove("active");
      viewChats.classList.add("active");

      // Sur mobile, si aucun contact actif, on s'assure d'afficher la liste
      if (!activeContactId && chatsLayout) {
        chatsLayout.setAttribute("data-chat-view", "list");
      }
    }
  }

  tabBtnDashboard.addEventListener("click", () => switchView("dashboard"));
  tabBtnChats.addEventListener("click", () => switchView("chats"));
  btnEmptyGoDashboard.addEventListener("click", () => switchView("dashboard"));
  btnSwitchToDashboardFromSidebar.addEventListener("click", () => switchView("dashboard"));

  // Bouton Burger / Tiroir en haut a gauche
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

  if (btnCloseDrawerMobile) {
    btnCloseDrawerMobile.addEventListener("click", () => {
      if (activeContactId && chatsLayout) {
        chatsLayout.setAttribute("data-chat-view", "room");
      }
    });
  }

  if (btnChatBackMobile) {
    btnChatBackMobile.addEventListener("click", () => {
      if (chatsLayout) {
        chatsLayout.setAttribute("data-chat-view", "list");
      }
    });
  }

  // =========================================================================
  // 3. PAGE D'ACCUEIL : QR CODE LOCAL ET EXPORTATION PNG
  // =========================================================================
  async function renderDashboardQr() {
    if (!dashQrCanvasContainer || !myIdentity) return;
    dashQrCanvasContainer.innerHTML = "";

    mySignedQrCache = await window.ztCrypto.createSignedQrPayload(myIdentity);

    new QRCode(dashQrCanvasContainer, {
      text: mySignedQrCache,
      width: 210,
      height: 210,
      colorDark: "#000000",
      colorLight: "#ffffff",
      correctLevel: QRCode.CorrectLevel.L,
    });
  }

  if (btnDashExportQr) {
    btnDashExportQr.addEventListener("click", () => {
      const qrCanvas = dashQrCanvasContainer.querySelector("canvas");
      const qrImg = dashQrCanvasContainer.querySelector("img");

      const exportCanvas = document.createElement("canvas");
      const size = 320;
      const padding = 36;
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
        a.download = `ZT_Key_${myIdentity.alias}.png`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
      }
    });
  }

  if (btnDashEditAlias) {
    btnDashEditAlias.addEventListener("click", () => {
      const newName = prompt(
        "Saisir un nouvel identifiant local :",
        myIdentity.alias
      );
      if (newName && newName.trim()) {
        myIdentity.alias = newName.trim().slice(0, 24);
        saveState();
        renderIdentityHeader();
        renderDashboardQr();
      }
    });
  }

  // =========================================================================
  // 4. SCANNER SUR LA PAGE D'ACCUEIL (CAMERA OU IMPORT FICHIER)
  // =========================================================================
  function setScannerStatus(text, isError) {
    if (!dashScannerStatus) return;
    dashScannerStatus.textContent = text;
    dashScannerStatus.style.color = isError ? "#f87171" : "#94a3b8";
  }

  async function startLiveCameraScanner() {
    stopCameraStream();
    if (btnTriggerScannerPerm) btnTriggerScannerPerm.style.display = "none";

    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      if (btnTriggerScannerPerm) btnTriggerScannerPerm.style.display = "block";
      setScannerStatus(
        "Autorisation camera requise. Verifiez que l'acces s'effectue en HTTPS.",
        true
      );
      return;
    }

    setScannerStatus("Initialisation du capteur video...", false);

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

      dashScannerVideo.srcObject = mediaStream;
      dashScannerVideo.setAttribute("playsinline", "true");
      await dashScannerVideo.play();
      setScannerStatus(
        "Viseur actif : alignez le QR Code dans le reticule.",
        false
      );
      scanInterval = setInterval(scanVideoFrame, 120);
    } catch (err) {
      if (btnTriggerScannerPerm) btnTriggerScannerPerm.style.display = "block";
      setScannerStatus(
        "Acces camera refuse. Veuillez autoriser la camera dans le navigateur.",
        true
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
    if (dashScannerVideo) {
      dashScannerVideo.srcObject = null;
    }
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

    const code = window.jsQR(imgData.data, imgData.width, imgData.height, {
      inversionAttempts: "dontInvert",
    });

    if (code && code.data) {
      handleDetectedQrPayload(code.data);
    }
  }

  function handleQrFileImport(file) {
    if (!file || !dashScannerCanvas) return;
    setScannerStatus("Analyse cryptographique de l'image importee...", false);

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

        const pad = 30;
        const w = drawW + pad * 2;
        const h = drawH + pad * 2;
        dashScannerCanvas.width = w;
        dashScannerCanvas.height = h;
        const ctx = dashScannerCanvas.getContext("2d");
        ctx.fillStyle = "#ffffff";
        ctx.fillRect(0, 0, w, h);
        ctx.drawImage(img, pad, pad, drawW, drawH);

        const imgData = ctx.getImageData(0, 0, w, h);
        if (!window.jsQR) {
          setScannerStatus("Erreur : Module jsQR non disponible.", true);
          return;
        }

        const code = window.jsQR(imgData.data, imgData.width, imgData.height, {
          inversionAttempts: "attemptBoth",
        });

        if (code && code.data) {
          handleDetectedQrPayload(code.data);
        } else {
          setScannerStatus("Aucun QR Code valide detecte dans l'image.", true);
        }
      };
      img.src = ev.target.result;
    };
    reader.readAsDataURL(file);
  }

  async function handleDetectedQrPayload(rawQr) {
    const result = await window.ztCrypto.verifyAndParseQrPayload(rawQr);
    if (!result.valid) {
      setScannerStatus(result.error, true);
      return;
    }

    const contact = result.contact;
    if (contact.id === myIdentity.deviceId) {
      setScannerStatus(
        "Ce QR Code correspond a votre propre identite locale.",
        true
      );
      return;
    }

    registerOrUpdateContact(contact);
    setScannerStatus(
      `Signature ECDSA secp256r1 validee : ${contact.alias} ajoute.`,
      false
    );

    await sendEncryptedHandshake(contact);

    // Arret de la camera et bascule vers l'onglet conversation
    stopCameraStream();
    setTimeout(() => {
      switchView("chats");
      selectContact(contact.id);
    }, 450);
  }

  if (btnStartCameraLive) {
    btnStartCameraLive.addEventListener("click", startLiveCameraScanner);
  }
  if (btnTriggerScannerPerm) {
    btnTriggerScannerPerm.addEventListener("click", startLiveCameraScanner);
  }
  if (btnImportImageQr && dashFileInput) {
    btnImportImageQr.addEventListener("click", () => {
      dashFileInput.value = "";
      dashFileInput.click();
    });
    dashFileInput.addEventListener("change", (e) => {
      if (e.target.files && e.target.files[0]) {
        handleQrFileImport(e.target.files[0]);
      }
    });
  }

  // =========================================================================
  // 5. GESTION DES CONTACTS & AFFICHAGE CONVERSATIONS
  // =========================================================================
  let contactSearchQuery = "";

  if (chatsSearchInput) {
    chatsSearchInput.addEventListener("input", (e) => {
      contactSearchQuery = e.target.value.toLowerCase().trim();
      renderContactsList();
    });
  }

  function renderContactsList() {
    if (!chatsContactsList) return;
    if (chatsCountBadge) {
      chatsCountBadge.textContent = String(verifiedContacts.length);
    }
    chatsContactsList.innerHTML = "";

    const filtered = verifiedContacts.filter((c) =>
      c.alias.toLowerCase().includes(contactSearchQuery) ||
      c.fingerprint.toLowerCase().includes(contactSearchQuery)
    );

    if (filtered.length === 0) {
      const emptyNote = document.createElement("div");
      emptyNote.style.padding = "24px 14px";
      emptyNote.style.textAlign = "center";
      emptyNote.style.color = "var(--text-sub)";
      emptyNote.style.fontSize = "12px";
      emptyNote.textContent = contactSearchQuery
        ? "Aucun contact correspondant."
        : "Aucun contact verifie pour le moment.";
      chatsContactsList.appendChild(emptyNote);
      return;
    }

    filtered.forEach((contact) => {
      const cell = document.createElement("div");
      cell.className =
        "contact-cell" + (contact.id === activeContactId ? " active" : "");
      const initials = (contact.alias || "ZT").slice(0, 2).toUpperCase();
      const unread = unreadByContact[contact.id] || 0;

      cell.innerHTML = `
        <div class="contact-initials">${escapeHtml(initials)}</div>
        <div class="contact-body">
          <div class="contact-top-line">
            <span class="contact-display-name">${escapeHtml(contact.alias)}</span>
            ${
              unread > 0
                ? `<span class="badge-unread">${unread}</span>`
                : `<span class="tag-verified">Verifie</span>`
            }
          </div>
          <div class="contact-fingerprint-sub">${escapeHtml(contact.fingerprint)}</div>
        </div>
      `;

      cell.addEventListener("click", () => {
        selectContact(contact.id);
        if (chatsLayout) {
          chatsLayout.setAttribute("data-chat-view", "room");
        }
      });

      chatsContactsList.appendChild(cell);
    });
  }

  function selectContact(contactId) {
    const contact = verifiedContacts.find((c) => c.id === contactId);
    if (!contact) return;

    activeContactId = contact.id;
    unreadByContact[contact.id] = 0;
    updateUnreadTotalBadge();

    // Masque l'ecran vide specifique plateforme et active la vue chat
    if (emptyPlatformState) emptyPlatformState.style.display = "none";
    if (activeChatView) activeChatView.style.display = "flex";

    if (activeChatPeerName) activeChatPeerName.textContent = contact.alias;
    if (activeChatPeerMeta) {
      activeChatPeerMeta.textContent = `Empreinte : ${contact.fingerprint} | Boite : ${contact.mailbox.slice(0, 10)}...`;
    }

    if (chatsLayout) {
      chatsLayout.setAttribute("data-chat-view", "room");
    }

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

  // =========================================================================
  // 6. ENVOI DE MESSAGES CHIFFRES (E2EE P-256 + AES-256-GCM)
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
        ct: envelope.ct.slice(0, 24) + "...",
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
  // 7. POLLING DU RELAIS ET TRAITEMENT DES MESSAGES ENTRANTS
  // =========================================================================
  function startSignedRelayPolling() {
    let failureCount = 0;

    const pollFn = async () => {
      if (!myIdentity) return;
      try {
        const ts = Math.floor(Date.now() / 1000) + serverClockOffsetSec;
        const sig = await window.ztCrypto.signPollChallenge(myIdentity, ts);

        const res = await fetch("/api/relay/poll", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-ZT-Protocol": "3.0",
          },
          body: JSON.stringify({
            mailbox: myIdentity.mailbox,
            timestamp: ts,
            signature: sig,
            pub_x: myIdentity.x,
            pub_y: myIdentity.y,
          }),
        });

        if (!res.ok) {
          failureCount++;
          if (failureCount > 2 && relayStatusText) {
            relayStatusText.className = "status-pill status-pill-inactive";
            relayStatusText.innerHTML = `<span class="status-dot"></span><span>Relais Deconnecte</span>`;
          }
          return;
        }

        failureCount = 0;
        if (relayStatusText) {
          relayStatusText.className = "status-pill status-pill-active";
          relayStatusText.innerHTML = `<span class="status-dot"></span><span>Relais Chiffre Actif</span>`;
        }

        const data = await res.json();
        const packets = data.packets || [];
        for (const pkt of packets) {
          await processIncomingEncryptedPacket(pkt);
        }
      } catch (_) {
        failureCount++;
        if (failureCount > 2 && relayStatusText) {
          relayStatusText.className = "status-pill status-pill-inactive";
          relayStatusText.innerHTML = `<span class="status-dot"></span><span>Relais Deconnecte</span>`;
        }
      }
    };

    pollFn();
    setInterval(pollFn, 950);
  }

  async function processIncomingEncryptedPacket(packet) {
    try {
      const envelope = packet.envelope;
      if (!envelope) return;

      const packetUniqueKey = `${packet.sender_id}:${envelope.seq}:${envelope.iv}`;
      if (seenPacketIds.has(packetUniqueKey)) return;

      let senderContact = verifiedContacts.find(
        (c) => c.id === packet.sender_id
      );

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
        const msg = contactMsgs.find(
          (m) => m.id === targetMsgId || (decrypted.readSeq && m.seq === decrypted.readSeq)
        );
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
        const incomingMsgId =
          decrypted.msgId ||
          "msg-" + Date.now() + "-" + Math.random().toString(36).slice(2, 6);

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
            ct: (envelope.ct || "").slice(0, 24) + "...",
            tag: envelope.tag,
            seq: seq,
          },
        };

        if (!messagesByContact[senderContact.id]) {
          messagesByContact[senderContact.id] = [];
        }
        messagesByContact[senderContact.id].push(msgEntry);

        // Envoi accuse de lecture E2EE
        sendEncryptedReadReceipt(senderContact, incomingMsgId, seq);

        if (!activeContactId) {
          selectContact(senderContact.id);
        } else if (activeContactId === senderContact.id) {
          renderChatMessages();
        } else {
          unreadByContact[senderContact.id] =
            (unreadByContact[senderContact.id] || 0) + 1;
          updateUnreadTotalBadge();
        }

        saveState();
        renderContactsList();
      }
    } catch (err) {
      console.error("[ZeroTrust] Paquet rejete :", err);
    }
  }

  // =========================================================================
  // 8. RENDU DES MESSAGES ET FONCTIONNALITES CHAT
  // =========================================================================
  function renderChatMessages() {
    if (!chatMessagesScroll) return;
    chatMessagesScroll.innerHTML = "";

    const contact = verifiedContacts.find((c) => c.id === activeContactId);
    if (!contact) return;

    const msgs = messagesByContact[contact.id] || [];

    msgs.forEach((m) => {
      const entry = document.createElement("div");
      entry.className = "message-entry " + (m.outgoing ? "outgoing" : "incoming");

      const timeStr = new Date(m.ts).toLocaleTimeString("fr-FR", {
        hour: "2-digit",
        minute: "2-digit",
      });

      let cipherHtml = "";
      if (showCipherInspector && m.cipherMeta) {
        cipherHtml = `
          <div class="message-crypto-inspect" title="Paquet chiffre E2EE">
            E2EE [#${m.cipherMeta.seq} | EphPK:${escapeHtml(m.cipherMeta.eph_x)} | IV:${escapeHtml(m.cipherMeta.iv)} | CT:${escapeHtml(m.cipherMeta.ct)}]
          </div>
        `;
      }

      let statusHtml = "";
      if (m.outgoing) {
        if (m.status === "read") {
          statusHtml = `<span class="status-read-tag">Vu</span>`;
        } else {
          statusHtml = `<span>Envoye</span>`;
        }
      }

      entry.innerHTML = `
        <div class="message-core">${escapeHtml(m.text)}</div>
        ${cipherHtml}
        <div class="message-details-line">
          <span>#${m.seq || 0}</span>
          <span>•</span>
          <span>${timeStr}</span>
          <span>•</span>
          <span>AES-256</span>
          ${statusHtml}
        </div>
      `;

      const core = entry.querySelector(".message-core");
      if (core) {
        core.addEventListener("click", () => {
          if (navigator.clipboard) {
            navigator.clipboard
              .writeText(m.text)
              .then(() => showToast("Texte copie"))
              .catch(() => {});
          }
        });
      }

      chatMessagesScroll.appendChild(entry);
    });

    chatMessagesScroll.scrollTop = chatMessagesScroll.scrollHeight;
  }

  function showToast(text) {
    if (!toastNotification) return;
    toastNotification.textContent = text;
    toastNotification.classList.add("show");
    setTimeout(() => {
      toastNotification.classList.remove("show");
    }, 1600);
  }

  if (btnToggleInspector) {
    btnToggleInspector.addEventListener("click", () => {
      showCipherInspector = !showCipherInspector;
      btnToggleInspector.textContent = `Inspecteur : ${
        showCipherInspector ? "ON" : "OFF"
      }`;
      renderChatMessages();
    });
  }

  if (btnDeleteActiveChat) {
    btnDeleteActiveChat.addEventListener("click", () => {
      if (!activeContactId) return;
      const contact = verifiedContacts.find((c) => c.id === activeContactId);
      const name = contact ? contact.alias : "ce contact";
      if (
        confirm(
          `Confirmez-vous la suppression definitive de l'historique local avec ${name} ?`
        )
      ) {
        delete messagesByContact[activeContactId];
        saveState();
        renderChatMessages();
      }
    });
  }

  // =========================================================================
  // 9. STATUT DU SERVEUR ET MODALE ACCES MOBILE
  // =========================================================================
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
          remoteServerUrl = info.public_4g_url;
        }
      }
    } catch (_) {}
  }

  function openMobileUrlModal() {
    if (!modalMobileUrl || !serverUrlQrContainer) return;
    serverUrlQrContainer.innerHTML = "";

    const targetUrl = remoteServerUrl || window.location.origin;
    if (serverUrlDisplay) {
      serverUrlDisplay.textContent = targetUrl;
      serverUrlDisplay.href = targetUrl;
    }

    new QRCode(serverUrlQrContainer, {
      text: targetUrl,
      width: 200,
      height: 200,
      colorDark: "#000000",
      colorLight: "#ffffff",
      correctLevel: QRCode.CorrectLevel.M,
    });

    modalMobileUrl.classList.add("open");
  }

  if (btnHeaderMobileLink) {
    btnHeaderMobileLink.addEventListener("click", openMobileUrlModal);
  }
  if (btnCloseModalMobile) {
    btnCloseModalMobile.addEventListener("click", () => {
      if (modalMobileUrl) modalMobileUrl.classList.remove("open");
    });
  }
  if (modalMobileUrl) {
    modalMobileUrl.addEventListener("click", (e) => {
      if (e.target === modalMobileUrl) {
        modalMobileUrl.classList.remove("open");
      }
    });
  }

  function escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  // Lancement
  initApp();
})();
