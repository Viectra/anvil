import type { ItemSummaryDto } from "@anvil/ui";
import { assessPageContext, setNativeInputValue } from "../security/phishingGuard.js";
import type {
  AutofillCredentialDto,
  ExtensionRequest,
  ExtensionResponse,
  UrlMatchResponseDto,
} from "../shared/messages.js";
import { FormDetector, type DetectedCredentialFields } from "./formDetector.js";
import { ClosedShadowOverlay } from "./shadowOverlay.js";

function sendExtensionMessage<T>(req: ExtensionRequest): Promise<T> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(req, (resp: ExtensionResponse<T> | undefined) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (!resp) {
        reject(new Error("Réponse vide du worker Anvil"));
        return;
      }
      if (!resp.ok) {
        reject(new Error(resp.error));
        return;
      }
      resolve(resp.data);
    });
  });
}

let latestGroups: DetectedCredentialFields[] = [];

function topAndActiveUrls(): { topUrl: string; activeUrl: string; isIframe: boolean } {
  const isIframe = window !== window.top;
  let topUrl = window.location.href;
  try {
    if (window.top?.location?.href) {
      topUrl = window.top.location.href;
    }
  } catch {
    // Cross-origin top frame: fallback cleanly to document.referrer; background validates sender.tab.url.
    topUrl = document.referrer || window.location.href;
  }
  return { topUrl, activeUrl: window.location.href, isIframe };
}

async function injectCredentials(itemId: string): Promise<void> {
  const { topUrl, activeUrl, isIframe } = topAndActiveUrls();
  const localVerdict = assessPageContext(topUrl, activeUrl, isIframe);
  if (!localVerdict.allowed) {
    throw new Error(localVerdict.reasons[0] ?? "Remplissage refusé par la garde locale");
  }

  const creds = await sendExtensionMessage<AutofillCredentialDto>({
    type: "anvil:get-autofill-credentials",
    itemId,
    topFrameUrl: topUrl,
    activeFrameUrl: activeUrl,
    isIframe,
  });

  if (!creds.security.allowed) {
    throw new Error(creds.security.reasons.join("; "));
  }

  const target =
    latestGroups.find((g) => g.passwordInput !== null || g.usernameInput !== null || g.otpInput !== null) ??
    null;
  if (!target) {
    return;
  }

  if (target.usernameInput && creds.username) {
    setNativeInputValue(target.usernameInput, creds.username);
  }
  if (target.passwordInput && creds.password) {
    setNativeInputValue(target.passwordInput, creds.password);
  }
  if (target.otpInput && creds.totp_code) {
    setNativeInputValue(target.otpInput, creds.totp_code);
  }
}

const overlay = new ClosedShadowOverlay(
  async () => {
    const { topUrl, activeUrl, isIframe } = topAndActiveUrls();
    const localVerdict = assessPageContext(topUrl, activeUrl, isIframe);
    if (!localVerdict.allowed) {
      return { unlocked: false, security: localVerdict, items: [] as ItemSummaryDto[] };
    }
    const [status, matched] = await Promise.all([
      sendExtensionMessage<{ unlocked: boolean }>({ type: "anvil:status" }),
      sendExtensionMessage<UrlMatchResponseDto>({
        type: "anvil:match-tab-url",
        topFrameUrl: topUrl,
        activeFrameUrl: activeUrl,
        isIframe,
      }),
    ]);
    return {
      unlocked: status.unlocked,
      security: matched.security,
      items: matched.items,
    };
  },
  async (itemId) => {
    await injectCredentials(itemId);
  },
  async (submission) => {
    await sendExtensionMessage({
      type: "anvil:save-captured-credential",
      submission,
    });
  },
);

const detector = new FormDetector(
  (groups) => {
    latestGroups = groups;
    const triggerInputs: HTMLInputElement[] = [];
    for (const group of groups) {
      if (group.passwordInput) triggerInputs.push(group.passwordInput);
      else if (group.usernameInput) triggerInputs.push(group.usernameInput);
      else if (group.otpInput) triggerInputs.push(group.otpInput);
    }
    overlay.attachTriggers(triggerInputs);
  },
  (submission) => {
    const { topUrl, activeUrl, isIframe } = topAndActiveUrls();
    const verdict = assessPageContext(topUrl, activeUrl, isIframe);
    if (verdict.allowed && !isIframe) {
      overlay.showSaveBanner(submission);
    }
  },
);

detector.start();

chrome.runtime.onMessage.addListener((msg: { type?: string; itemId?: string }) => {
  if (msg?.type === "anvil:perform-fill" && msg.itemId) {
    void injectCredentials(msg.itemId);
  }
});
