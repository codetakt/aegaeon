function element(tag, text, parent = view) {
    const node = document.createElement(tag);
    if (text != null) node.textContent = text;
    parent.append(node);
    return node;
}
function heading(text) { element("h2", text); }
function paragraph(text) { element("p", text); }
function button(text, handler, secondary = false) {
    const control = element("button", text);
    control.type = "button";
    if (secondary) control.className = "secondary";
    control.addEventListener("click", handler);
}
function post(label, action, input = {}, secondary = false) {
    button(label, () => { void submit(action, input); }, secondary);
}
function requiredText(value) {
    if (typeof value !== "string" || value.trim() === "") throw new Error();
    return value;
}
function detail(list, term, value) {
    element("dt", term, list);
    element("dd", requiredText(value), list);
}
function account(state) {
    const list = element("dl");
    detail(list, "Signed-in account", state.account.identifier);
    detail(list, "Account subject", state.account.subject);
}
function loginNotice() {
    paragraph("Signing in replaces the active issuer login in this browser profile. Other applications can see the new account on their next single sign-on request. To keep accounts separate, open the original invitation in a separate browser profile.");
}
function newAccount() {
    loginNotice();
    post("Switch account", "switch", {}, true);
}
function deadline(seconds) {
    if (!Number.isSafeInteger(seconds) || seconds < 1) throw new Error();
    return new Date(seconds * 1000).toLocaleString(undefined, {
        dateStyle: "medium", timeStyle: "long"
    });
}
function budget(slots) {
    if (!Number.isInteger(slots) || slots < 0 || slots > 5) throw new Error();
    paragraph(slots + " of 5 challenge requests remaining across all devices.");
}
function field(form, text, type, name, limits) {
    const label = element("label", text, form);
    const input = element("input", null, label);
    Object.assign(input, {type, name, required: true}, limits);
    return input;
}
function form(text, collect) {
    const block = element("form");
    block.method = "post";
    const values = collect(block);
    const control = element("button", text, block);
    control.type = "submit";
    block.addEventListener("submit", event => {
        event.preventDefault();
        if (!sending && block.reportValidity()) values();
    });
}
function identityOptions(state) {
    if (state.canRegister || state.canRecover) {
        paragraph("Registration and recovery use a separate email proof. Each request uses one of five identity requests and can expire in up to ten minutes. You will sign in separately afterward.");
    }
    if (state.canRegister) post("Send registration email", "identityRequest", {purpose: "registration"});
    if (state.canRecover) form("Send recovery email", block => {
        const login = field(block, "Login identifier", "text", "loginIdentifier",
            {maxLength: 255, autocomplete: "username"});
        return () => { void submit("identityRequest", {purpose: "password_recovery", loginIdentifier: login.value}); };
    });
}
function completeIdentity() {
    heading("Set your password");
    paragraph("Saving your credentials completes the address check. You will then sign in to continue.");
    form("Save credentials", block => {
        const options = {minLength: 12, maxLength: 1024, autocomplete: "new-password"};
        const password = field(block, "New password", "password", "password", options);
        const repeat = field(block, "Confirm password", "password", "passwordConfirmation", options);
        return () => {
            if (password.value !== repeat.value) {
                repeat.setCustomValidity("The two passwords must match.");
                repeat.reportValidity();
                repeat.addEventListener("input", () => repeat.setCustomValidity(""), {once: true});
                password.addEventListener("input", () => repeat.setCustomValidity(""), {once: true});
                return;
            }
            const input = {password: password.value, passwordConfirmation: repeat.value};
            password.value = ""; repeat.value = "";
            void submit("identityComplete", input);
        };
    });
}
function verifyAccount(state) {
    const preview = state.preview;
    if (!preview || preview.issuer !== configuration.issuer || !uuid.test(preview.organizationId) ||
        preview.organizationId === nil || !Array.isArray(preview.roles)) throw new Error();
    heading("Confirm organization membership");
    account(state);
    const list = element("dl");
    detail(list, "Issuer", preview.issuer);
    detail(list, "Organization", preview.organizationName);
    detail(list, "Organization ID", preview.organizationId);
    element("h2", "Offered roles");
    const roles = element("dl");
    for (const role of preview.roles) detail(roles, requiredText(role.label), role.key);
    if (!preview.roles.length) paragraph("No additional roles.");
    paragraph("Joining creates membership for the account shown above.");
    post("Accept and join organization", "confirm", {confirmation: requiredText(state.confirmation)});
    newAccount();
}
function originalBrowser() {
    paragraph("Open the email link in the browser profile where you requested it. If you are on a different device, open the original invitation there, sign in and explicitly request a new challenge.");
}
function render(state) {
    view.replaceChildren();
    switch (state.step) {
    case "invitation":
        heading("Continue your invitation");
        if (state.signInPending) {
            paragraph("You have already started signing in. To register or recover your account instead, cancel this flow and reopen the original invitation email.");
            loginNotice(); post("Continue sign-in", "login"); break;
        }
        paragraph("Sign in to prove control of the invited address and review the organization and roles before joining.");
        loginNotice(); post("Sign in", "login"); identityOptions(state); break;
    case "loginUnavailable":
        heading("Sign-in is temporarily unavailable");
        paragraph("The issuer could not complete sign-in. No verification email was sent. Sign in again to continue.");
        loginNotice(); post("Sign in again", "login"); break;
    case "signedIn":
        heading("Verify the invited address");
        account(state); post("Check available challenge requests", "status"); newAccount(); break;
    case "identityWaiting":
        heading("Check your email");
        paragraph("Open the registration or recovery message in the same browser profile."); break;
    case "identityReady":
        completeIdentity(); break;
    case "sendReady":
        heading("Send a verification email");
        account(state); budget(state.remainingChallenges);
        if (state.remainingChallenges > 0) {
            paragraph("Sending uses one request. The link expires no later than " + deadline(state.expiresAt) + ". A delivery retry can take at least 60 seconds.");
            post("Send verification email", "send", {confirmation: requiredText(state.confirmation)});
        } else {
            paragraph("If you still have a live challenge, open its email here. Otherwise contact the inviter for a new invitation.");
        }
        newAccount(); break;
    case "sendPending":
        heading("Check the pending send");
        paragraph("The first request may already have queued the message. Retry that same request to check.");
        post("Retry the same send", "send", {confirmation: requiredText(state.confirmation)}); break;
    case "challengeWaiting":
        heading("Open the verification email");
        paragraph("Complete the address check before " + deadline(state.expiresAt) + ".");
        budget(state.remainingChallenges); originalBrowser();
        if (state.remainingChallenges > 0) post("Review a replacement request", "status");
        newAccount(); break;
    case "proofReady":
        heading("Review the invitation");
        account(state); post("Show invitation details", "preview"); newAccount(); break;
    case "confirm":
        verifyAccount(state); break;
    case "acceptPending":
        heading("Check acceptance");
        paragraph("A response was lost. Retry the same confirmation while your original proofs are live.");
        post("Retry the same acceptance", "confirm", {confirmation: requiredText(state.confirmation)}); break;
    case "metadataUnavailable":
        heading("Invitation details are unavailable");
        paragraph("Invitation details are unavailable. Contact the domain operator, then try again before the displayed deadline.");
        if (state.expiresAt != null) paragraph("Deadline: " + deadline(state.expiresAt));
        button("Check current step", () => location.reload()); break;
    case "exhausted":
        heading("No more challenges available");
        paragraph("A current challenge can still complete. If its deadline has passed, contact the inviter for a new invitation."); break;
    case "expired":
        heading("The challenge has expired");
        paragraph("Review the remaining requests before deciding whether to send another email.");
        post("Check remaining requests", "status"); break;
    case "restart":
        heading("Restart this invitation");
        paragraph("Restarting discards the earlier challenge. The invitation retains its original request budget.");
        post("Restart invitation", "restart"); break;
    case "complete":
        heading("Invitation accepted");
        paragraph("Your membership was recorded. Sign in to the application again to use it.");
        if (state.canReturn === true) post("Return to application", "return"); return;
    case "unconfirmed":
        heading("Outcome unconfirmed");
        paragraph("Check your membership using an independently authorized application."); return;
    case "closed":
        heading("Invitation flow closed");
        paragraph("To start again, reopen the original invitation email."); return;
    case "unavailable":
        invalidLink(); return;
    default:
        throw new Error();
    }
    post("Cancel invitation flow", "cancel", {}, true);
}
