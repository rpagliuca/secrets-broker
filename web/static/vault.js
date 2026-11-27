// Opening the vault with a passkey. The WebAuthn PRF extension gives, after
// user verification, a fixed secret of the passkey; an X25519 key comes out
// of it, which decrypts the vault key stored on the server. The scheme is
// the server's (vault.go): X25519, HKDF-SHA256 and AES-256-GCM. The HKDF
// labels are part of the stored files and must not change.
globalThis.Vault = (() => {
  const enc = new TextEncoder();
  const WRAP_INFO = enc.encode("secrets-broker-web cofre v1");
  const PRF_INFO = enc.encode("secrets-broker-web prf v1");
  // PKCS#8 header of an X25519 private key; the 32 bytes come after it.
  const PKCS8 = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);

  const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));
  const fromB64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const concat = (a, b) => {
    const r = new Uint8Array(a.length + b.length);
    r.set(a);
    r.set(b, a.length);
    return r;
  };

  const hkdf = async (secret, salt, info) => {
    const k = await crypto.subtle.importKey("raw", secret, "HKDF", false, ["deriveBits"]);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, k, 256));
  };
  const publicX = (raw) => crypto.subtle.importKey("raw", raw, { name: "X25519" }, true, []);
  const exchange = async (priv, pubRaw) =>
    new Uint8Array(await crypto.subtle.deriveBits({ name: "X25519", public: await publicX(pubRaw) }, priv, 256));
  const aes = async (shared, eph, to, uses) =>
    crypto.subtle.importKey("raw", await hkdf(shared, concat(eph, to), WRAP_INFO), "AES-GCM", false, uses);

  // passkeyKey: from the PRF secret to the X25519 private key and its public key.
  const passkeyKey = async (prf) => {
    const seed = await hkdf(new Uint8Array(prf), new Uint8Array(32), PRF_INFO);
    const priv = await crypto.subtle.importKey("pkcs8", concat(PKCS8, seed), { name: "X25519" }, false, ["deriveBits"]);
    seed.fill(0);
    const base = new Uint8Array(32);
    base[0] = 9; // the curve's base point: the exchange with it gives the public key
    return { priv, pub: await exchange(priv, base) };
  };

  // unwrap decrypts an envelope {ephemeral, nonce, ciphertext} made for this key.
  const unwrap = async (key, e) => {
    const eph = fromB64(e.ephemeral);
    const k = await aes(await exchange(key.priv, eph), eph, key.pub, ["decrypt"]);
    return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(e.nonce) }, k, fromB64(e.ciphertext)));
  };

  // wrap encrypts plain for a public key (base64).
  const wrap = async (toB64, plain) => {
    const to = fromB64(toB64);
    const pair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
    const eph = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    const k = await aes(await exchange(pair.privateKey, to), eph, to, ["encrypt"]);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, k, plain);
    return { ephemeral: b64(eph), nonce: b64(nonce), ciphertext: b64(ct) };
  };

  return { passkeyKey, unwrap, wrap, b64, fromB64 };
})();

// The /vault page. Outside a browser (in tests) this part does not run.
if (typeof document !== "undefined") {
  (() => {
    const text = (k) => document.body.dataset[k] || "";
    const fromB64url = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    const toB64url = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const showError = (t) => {
      const p = document.getElementById("error");
      p.textContent = t;
      p.hidden = false;
      p.scrollIntoView({ block: "center" });
    };
    const call = async (path, body) => {
      const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(data.message || "error " + r.status);
      return data;
    };

    // Signs with the passkey asking for the PRF; returns the signature and the secret.
    const signWithPRF = async (begin) => {
      const pk = begin.options.publicKey;
      pk.challenge = fromB64url(pk.challenge);
      (pk.allowCredentials || []).forEach((c) => (c.id = fromB64url(c.id)));
      pk.extensions = { ...(pk.extensions || {}), prf: { eval: { first: Vault.fromB64(begin.salt) } } };
      const c = await navigator.credentials.get({ publicKey: pk });
      const ext = c.getClientExtensionResults();
      const prf = ext && ext.prf && ext.prf.results && ext.prf.results.first;
      if (!prf) throw new Error(text("noPrf"));
      const signature = {
        id: c.id,
        rawId: toB64url(c.rawId),
        type: c.type,
        clientExtensionResults: {},
        response: {
          clientDataJSON: toB64url(c.response.clientDataJSON),
          authenticatorData: toB64url(c.response.authenticatorData),
          signature: toB64url(c.response.signature),
          userHandle: c.response.userHandle ? toB64url(c.response.userHandle) : undefined,
        },
      };
      return { signature, prf };
    };

    const bind = (id, act) => {
      const button = document.getElementById(id);
      if (!button) return;
      button.addEventListener("click", async () => {
        button.disabled = true;
        try {
          location.href = "/vault?notice=" + encodeURIComponent(await act());
        } catch (e) {
          showError(text("vaultFailed") + " " + e.message);
          button.disabled = false;
        }
      });
    };

    bind("enable-passkey", async () => {
      const begin = await call("/vault/prf/begin");
      const { signature, prf } = await signWithPRF(begin);
      const key = await Vault.passkeyKey(prf);
      const end = await call("/vault/prf/finish?token=" + encodeURIComponent(begin.token), { signature, public: Vault.b64(key.pub) });
      return end.notice;
    });

    bind("open-vault", async () => {
      const begin = await call("/vault/open/begin");
      const { signature, prf } = await signWithPRF(begin);
      const key = await Vault.passkeyKey(prf);
      // The server sends an envelope per passkey; the signing one's counts.
      const envelope = begin.envelopes[signature.rawId];
      if (!envelope) throw new Error(text("noEnvelope"));
      const plain = await Vault.unwrap(key, envelope);
      const answer = await Vault.wrap(begin.reply_to, plain);
      plain.fill(0);
      const end = await call("/vault/open/finish?token=" + encodeURIComponent(begin.token), { signature, key: answer });
      return end.notice;
    });
  })();
}
