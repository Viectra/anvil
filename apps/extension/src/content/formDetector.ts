import type { CapturedSubmissionDto } from "../shared/messages.js";

export interface DetectedCredentialFields {
  form: HTMLFormElement | null;
  usernameInput: HTMLInputElement | null;
  passwordInput: HTMLInputElement | null;
  otpInput: HTMLInputElement | null;
}

const USERNAME_HINTS = /(user|login|email|ident|account|handle|matricule)/i;
const OTP_HINTS = /(otp|totp|2fa|mfa|token|pin|verification|code)/i;

function isVisibleInput(el: HTMLInputElement): boolean {
  if (el.disabled || el.type === "hidden") return false;
  const style = window.getComputedStyle(el);
  if (style.display === "none" || style.visibility === "hidden") return false;
  const rect = el.getBoundingClientRect();
  return rect.width > 12 && rect.height > 12;
}

function classifyOtpInput(el: HTMLInputElement): boolean {
  if (el.autocomplete === "one-time-code") return true;
  const hay = `${el.name} ${el.id} ${el.placeholder} ${el.getAttribute("aria-label") ?? ""}`;
  return OTP_HINTS.test(hay) && el.maxLength > 0 && el.maxLength <= 8;
}

function classifyUsernameInput(el: HTMLInputElement): boolean {
  if (el.type !== "text" && el.type !== "email" && el.type !== "tel") {
    return false;
  }
  if (el.autocomplete === "username" || el.autocomplete === "email") return true;
  if (el.type === "email") return true;
  const hay = `${el.name} ${el.id} ${el.placeholder} ${el.getAttribute("aria-label") ?? ""}`;
  return USERNAME_HINTS.test(hay);
}

/** Scans the active document (or SPA subtrees) for credential/OTP inputs and form submissions. */
export class FormDetector {
  private observer: MutationObserver | null = null;
  private boundForms = new WeakSet<HTMLFormElement>();
  private boundPasswordChanges = new WeakMap<HTMLInputElement, string>();

  constructor(
    private readonly onFieldsDiscovered: (groups: DetectedCredentialFields[]) => void,
    private readonly onSubmissionCaptured: (submission: CapturedSubmissionDto) => void,
  ) {}

  start(): void {
    this.scan();
    this.observer = new MutationObserver(() => {
      this.scan();
    });
    this.observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });
  }

  stop(): void {
    this.observer?.disconnect();
    this.observer = null;
  }

  scan(): DetectedCredentialFields[] {
    const inputs = Array.from(document.querySelectorAll("input")).filter(isVisibleInput);
    const groupsMap = new Map<HTMLFormElement | null, DetectedCredentialFields>();

    for (const input of inputs) {
      const form = input.form ?? null;
      let group = groupsMap.get(form);
      if (!group) {
        group = { form, usernameInput: null, passwordInput: null, otpInput: null };
        groupsMap.set(form, group);
      }

      if (input.type === "password" && !group.passwordInput) {
        group.passwordInput = input;
        this.watchPasswordInput(input);
      } else if (classifyOtpInput(input) && !group.otpInput) {
        group.otpInput = input;
      } else if (classifyUsernameInput(input) && !group.usernameInput) {
        group.usernameInput = input;
      }
    }

    const groups = Array.from(groupsMap.values()).filter(
      (g) => g.passwordInput !== null || g.usernameInput !== null || g.otpInput !== null,
    );

    for (const group of groups) {
      if (group.form && !this.boundForms.has(group.form)) {
        this.boundForms.add(group.form);
        group.form.addEventListener("submit", () => {
          this.captureFromGroup(group);
        });
      }
    }

    this.onFieldsDiscovered(groups);
    return groups;
  }

  private watchPasswordInput(pwInput: HTMLInputElement): void {
    if (this.boundPasswordChanges.has(pwInput)) {
      return;
    }
    this.boundPasswordChanges.set(pwInput, pwInput.value);
    pwInput.addEventListener("change", () => {
      this.boundPasswordChanges.set(pwInput, pwInput.value);
    });
  }

  private captureFromGroup(group: DetectedCredentialFields): void {
    const password = group.passwordInput?.value ?? "";
    const username = group.usernameInput?.value ?? "";
    if (!password || (!username && group.passwordInput?.autocomplete !== "new-password")) {
      return;
    }
    const isPasswordChange =
      group.passwordInput?.autocomplete === "new-password" ||
      Boolean(group.form?.querySelector('input[type="password"][autocomplete="new-password"]'));

    this.onSubmissionCaptured({
      pageUrl: window.location.href,
      pageTitle: document.title,
      username,
      password,
      isPasswordChange,
    });
  }
}
