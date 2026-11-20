// Remove even malformed fragments before inspecting input or initiating I/O.
// A redirect with a fragment can otherwise forward it to the next origin.
const entry = new URL(location.href);
let mail = entry.hash;
entry.hash = "";
history.replaceState(null, "", entry.pathname + entry.search);
const configuration = document.currentScript.dataset;
const view = document.getElementById("view");
const landingPath = "/organization-invitations/hosted";
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const nil = "00000000-0000-0000-0000-000000000000";
const opaque = /^[a-zA-Z0-9_-]{16,256}$/;
const fields = new Set(["issuer", "environmentId", "domainId", "invitationId", "objectId",
    "template", "deliveryRevision", "capability", "expiresAt"]);
let csrf = configuration.csrf;
let flow = null;
let sending = false;

function base64url(encoded, limit) {
    if (!encoded || encoded.length > Math.ceil(limit * 8 / 6) ||
        /[^a-zA-Z0-9_-]/.test(encoded)) throw new Error();
    const normalized = encoded.replaceAll("-", "+").replaceAll("_", "/");
    const binary = atob(normalized);
    if (binary.length > limit || btoa(binary).replace(/=+$/, "") !== normalized) throw new Error();
    return Uint8Array.from(binary, c => c.charCodeAt(0));
}

// The v2 object is flat. Tokenize its keys before JSON.parse can discard a
// duplicate, including equivalent escaped spellings. JSON.parse then enforces
// the JSON grammar. Integers are checked lexically to reject 1.0 and 1e0.
function readObject(text) {
    const tokens = /"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[\da-fA-F]{4}))*"|[{}:,]|-?(?:0|[1-9][0-9]*)|[ \n\t\r]+/gy;
    let end = 0;
    const seen = new Set();
    let nextKey = false;
    while (end < text.length) {
        const match = tokens.exec(text);
        if (!match) throw new Error();
        end = tokens.lastIndex;
        const token = match[0];
        if (token.trim() === "") continue;
        if (nextKey) {
            const key = JSON.parse(token);
            if (!fields.has(key) || seen.has(key)) throw new Error();
            seen.add(key);
        }
        nextKey = token === "{" || token === ",";
    }
    if (seen.size !== fields.size) throw new Error();
    return JSON.parse(text);
}

function validateMail(fragment) {
    if (!fragment.startsWith("#aegaeon=")) throw new Error();
    const encoded = fragment.slice(9);
    const bytes = base64url(encoded, 8192);
    // v2 is UTF-8 JSON without a BOM. Retaining the BOM makes it invalid JSON.
    const link = readObject(new TextDecoder("utf-8", {fatal: true, ignoreBOM: true}).decode(bytes));
    if (link.issuer !== configuration.issuer || link.environmentId !== configuration.environment ||
        !["environmentId", "domainId", "invitationId", "objectId"].every(key =>
            typeof link[key] === "string" && uuid.test(link[key]) && link[key] !== nil) ||
        !["organization_invitation", "organization_recipient_challenge", "organization_identity_registration",
            "organization_identity_recovery"].includes(link.template) ||
        ((link.invitationId === link.objectId) !== (link.template === "organization_invitation")) ||
        !Number.isInteger(link.deliveryRevision) || link.deliveryRevision < 1 || link.deliveryRevision > 5 ||
        !Number.isSafeInteger(link.expiresAt) || link.expiresAt <= Number(configuration.now) ||
        link.expiresAt > Number(configuration.now) + 86400 ||
        typeof link.capability !== "string" || base64url(link.capability, 32).length !== 32) throw new Error();
    return encoded;
}

function invalidLink() {
    view.replaceChildren();
    heading("Unable to open this invitation");
    paragraph("Open the original invitation from your email. Use the same browser profile for an address or challenge link. If the invitation remains unavailable, contact the inviter.");
}

function changeLocation(href, action) {
    const destination = new URL(href, configuration.issuer);
    if (destination.protocol !== "https:" || destination.username || destination.password ||
        destination.hash) throw new Error();
    if (action !== "return" && (!["login", "switch"].includes(action) ||
        destination.origin !== location.origin || destination.pathname !== "/authorize")) throw new Error();
    location.assign(destination.href);
}

async function submit(action, input = {}) {
    if (sending) return;
    sending = true;
    view.querySelectorAll("button").forEach(button => { button.disabled = true; });
    try {
        const body = {action, ...input};
        if (flow !== null) body.flow = flow;
        const response = await fetch(landingPath + "/actions", {
            method: "POST", mode: "same-origin", credentials: "same-origin", redirect: "error",
            cache: "no-store", referrerPolicy: "no-referrer",
            headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
            body: JSON.stringify(body)
        });
        if (!response.ok && action === "import") { invalidLink(); return; }
        if (!response.ok) throw new Error();
        const state = await response.json();
        if (state.navigateTo) { changeLocation(state.navigateTo, action); return; }
        if (state.flow != null) {
            if (typeof state.flow !== "string" || !opaque.test(state.flow)) throw new Error();
            flow = state.flow;
            history.replaceState(null, "", landingPath + "?flow=" + encodeURIComponent(flow));
        }
        if (state.csrfToken != null) {
            if (typeof state.csrfToken !== "string" || !state.csrfToken) throw new Error();
            csrf = state.csrfToken;
        }
        render(state);
    } catch {
        view.replaceChildren();
        heading("Unable to confirm this step");
        if (action === "confirm") paragraph("Outcome unconfirmed. Check your membership using an independently authorized application before starting again.");
        if (flow) {
            paragraph("You can check the current step without sending a new message.");
            button("Check current step", () => location.reload());
        } else {
            paragraph("Reopen the original invitation email in the browser where you started.");
        }
    } finally {
        sending = false;
    }
}

function importMail(fragment) {
    try { void submit("import", {fragment: validateMail(fragment)}); }
    catch { invalidLink(); }
}

function start() {
    window.addEventListener("pagehide", () => { mail = ""; csrf = ""; view.replaceChildren(); });
    window.addEventListener("pageshow", event => { if (event.persisted) location.reload(); });
    if (entry.pathname !== landingPath) { invalidLink(); return; }
    // An already-open tab can receive another link as a same-document
    // navigation. Scrub that fragment synchronously, too.
    window.addEventListener("hashchange", () => {
        const fragment = location.hash;
        history.replaceState(null, "", location.pathname + location.search);
        if (!fragment) return;
        if (sending || flow || location.search) { invalidLink(); return; }
        importMail(fragment);
    });
    if (mail) {
        const fragment = mail;
        mail = "";
        if (entry.search) invalidLink();
        else importMail(fragment);
        return;
    }
    const handle = entry.searchParams.get("flow");
    if (handle && opaque.test(handle) && entry.search === "?flow=" + handle) {
        flow = handle;
        void submit("resume");
    } else invalidLink();
}
