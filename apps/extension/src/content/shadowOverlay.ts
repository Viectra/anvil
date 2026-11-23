import type { ItemSummaryDto } from "@anvil/ui";
import type { AutofillSecurityVerdictDto, CapturedSubmissionDto } from "../shared/messages.js";

const OVERLAY_CSS = `
  :host { all: initial; }
  .anvil-btn {
    position: fixed;
    z-index: 2147483645;
    width: 24px;
    height: 24px;
    border-radius: 6px;
    border: 1px solid #2A303E;
    background: #13151B;
    color: #E63946;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.45);
    transition: border-color 0.15s ease, transform 0.12s ease;
  }
  .anvil-btn:hover {
    border-color: #E07A2F;
    transform: scale(1.06);
  }
  .anvil-popover {
    position: fixed;
    z-index: 2147483646;
    width: 300px;
    border-radius: 10px;
    border: 1px solid #2A303E;
    background: #13151B;
    color: #F1F3F5;
    font-family: system-ui, -apple-system, sans-serif;
    font-size: 13px;
    box-shadow: 0 12px 30px rgba(0, 0, 0, 0.65);
    overflow: hidden;
  }
  .anvil-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 11px;
    background: #0B0C0F;
    border-bottom: 1px solid #222632;
    font-size: 11.5px;
    font-weight: 600;
  }
  .anvil-banner {
    padding: 7px 11px;
    font-size: 11.5px;
    border-bottom: 1px solid #222632;
  }
  .anvil-warn {
    background: rgba(244, 162, 97, 0.14);
    color: #F4A261;
  }
  .anvil-danger {
    background: rgba(224, 79, 95, 0.14);
    color: #E04F5F;
  }
  .anvil-list {
    max-height: 210px;
    overflow-y: auto;
    padding: 4px;
  }
  .anvil-item {
    width: 100%;
    border: 1px solid transparent;
    border-radius: 7px;
    background: transparent;
    color: #F1F3F5;
    padding: 7px 8px;
    display: flex;
    align-items: center;
    gap: 9px;
    text-align: left;
    cursor: pointer;
  }
  .anvil-item:hover {
    background: #1A1D24;
    border-color: #E07A2F;
  }
  .anvil-badge {
    width: 26px;
    height: 26px;
    border-radius: 6px;
    background: #1B1E26;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 700;
    font-size: 11px;
    flex-shrink: 0;
  }
  .anvil-save-toast {
    position: fixed;
    top: 14px;
    right: 14px;
    z-index: 2147483647;
    width: 336px;
    border-radius: 10px;
    border: 1px solid #E07A2F;
    background: #13151B;
    color: #F1F3F5;
    font-family: system-ui, -apple-system, sans-serif;
    padding: 12px 14px;
    box-shadow: 0 12px 32px rgba(0, 0, 0, 0.7);
  }
  .anvil-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 10px;
  }
  .anvil-btn-primary {
    border: none;
    border-radius: 6px;
    padding: 5px 11px;
    background: #E07A2F;
    color: #0B0C0F;
    font-weight: 600;
    cursor: pointer;
  }
  .anvil-btn-secondary {
    border: 1px solid #2A303E;
    border-radius: 6px;
    padding: 5px 11px;
    background: #1B1E26;
    color: #A0A8B8;
    cursor: pointer;
  }
`;

/** Closed Shadow DOM overlay host isolating inline triggers, picker, and save banner from host CSS/JS. */
export class ClosedShadowOverlay {
  private readonly hostEl: HTMLDivElement;
  private readonly shadow: ShadowRoot;
  private readonly buttonsContainer: HTMLDivElement;
  private readonly popoverEl: HTMLDivElement;
  private readonly saveContainer: HTMLDivElement;
  private activeAnchor: HTMLInputElement | null = null;
  private anchorButtons: Array<{ input: HTMLInputElement; button: HTMLButtonElement }> = [];

  constructor(
    private readonly onRequestMatches: () => Promise<{
      unlocked: boolean;
      security: AutofillSecurityVerdictDto;
      items: ItemSummaryDto[];
    }>,
    private readonly onPickItem: (itemId: string) => Promise<void>,
    private readonly onSaveSubmission: (submission: CapturedSubmissionDto) => Promise<void>,
  ) {
    this.hostEl = document.createElement("div");
    this.hostEl.setAttribute("data-anvil-overlay", "true");
    // Closed Shadow DOM keeps extension UI styling and state inaccessible to host page scripts.
    this.shadow = this.hostEl.attachShadow({ mode: "closed" });

    const style = document.createElement("style");
    style.textContent = OVERLAY_CSS;

    this.buttonsContainer = document.createElement("div");
    this.popoverEl = document.createElement("div");
    this.popoverEl.className = "anvil-popover";
    this.popoverEl.hidden = true;
    this.saveContainer = document.createElement("div");

    this.shadow.append(style, this.buttonsContainer, this.popoverEl, this.saveContainer);
    document.documentElement.appendChild(this.hostEl);

    window.addEventListener("scroll", () => this.reposition(), { passive: true });
    window.addEventListener("resize", () => this.reposition(), { passive: true });
    document.addEventListener("click", (event) => {
      if (event.target !== this.hostEl) {
        this.closePopover();
      }
    });
  }

  attachTriggers(inputs: HTMLInputElement[]): void {
    this.buttonsContainer.replaceChildren();
    this.anchorButtons = [];

    for (const input of inputs) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "anvil-btn";
      btn.title = "Remplir avec Anvil";
      btn.innerHTML =
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="14" height="14" fill="#E63946"><path fill-rule="evenodd" clip-rule="evenodd" d="M8.2 2.5H15.8L20.5 6.4V13.4L12 21.8L3.5 13.4V6.4L8.2 2.5ZM5.5 8.8H18.5V10.6H16L14.3 12.1V15L16.5 16.8V18H7.5V16.8L9.7 15V12.1L8 10.6L5.5 9.8V8.8Z"/></svg>';
      btn.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        void this.openPopover(input);
      });
      this.buttonsContainer.appendChild(btn);
      this.anchorButtons.push({ input, button: btn });
    }
    this.reposition();
  }

  reposition(): void {
    for (const { input, button } of this.anchorButtons) {
      if (!document.contains(input)) {
        button.style.display = "none";
        continue;
      }
      const rect = input.getBoundingClientRect();
      if (rect.width < 20 || rect.height < 14) {
        button.style.display = "none";
        continue;
      }
      button.style.display = "inline-flex";
      button.style.top = `${Math.max(4, rect.top + (rect.height - 24) / 2)}px`;
      button.style.left = `${Math.max(4, rect.right - 30)}px`;
    }

    if (!this.popoverEl.hidden && this.activeAnchor) {
      const rect = this.activeAnchor.getBoundingClientRect();
      this.popoverEl.style.top = `${Math.min(window.innerHeight - 260, rect.bottom + 6)}px`;
      this.popoverEl.style.left = `${Math.max(8, Math.min(window.innerWidth - 310, rect.left))}px`;
    }
  }

  closePopover(): void {
    this.popoverEl.hidden = true;
    this.activeAnchor = null;
  }

  showSaveBanner(submission: CapturedSubmissionDto): void {
    this.saveContainer.replaceChildren();
    const card = document.createElement("div");
    card.className = "anvil-save-toast";

    const title = document.createElement("div");
    title.style.fontWeight = "600";
    title.style.fontSize = "13px";
    title.textContent = submission.isPasswordChange
      ? "Mettre à jour dans Anvil ?"
      : "Enregistrer dans Anvil ?";

    const sub = document.createElement("div");
    sub.style.color = "#A0A8B8";
    sub.style.fontSize = "12px";
    sub.style.marginTop = "4px";
    sub.textContent = `${submission.username || "Compte détecté"} — ${new URL(submission.pageUrl).hostname}`;

    const actions = document.createElement("div");
    actions.className = "anvil-actions";

    const cancelBtn = document.createElement("button");
    cancelBtn.type = "button";
    cancelBtn.className = "anvil-btn-secondary";
    cancelBtn.textContent = "Ignorer";
    cancelBtn.addEventListener("click", () => this.saveContainer.replaceChildren());

    const saveBtn = document.createElement("button");
    saveBtn.type = "button";
    saveBtn.className = "anvil-btn-primary";
    saveBtn.textContent = submission.isPasswordChange ? "Mettre à jour" : "Enregistrer";
    saveBtn.addEventListener("click", () => {
      void this.onSaveSubmission(submission).finally(() => this.saveContainer.replaceChildren());
    });

    actions.append(cancelBtn, saveBtn);
    card.append(title, sub, actions);
    this.saveContainer.appendChild(card);
  }

  private async openPopover(anchor: HTMLInputElement): Promise<void> {
    this.activeAnchor = anchor;
    this.popoverEl.replaceChildren();
    this.popoverEl.hidden = false;
    this.reposition();

    const header = document.createElement("div");
    header.className = "anvil-header";
    header.textContent = "Anvil — Remplissage chiffré";
    this.popoverEl.appendChild(header);

    const state = await this.onRequestMatches();
    if (!state.security.allowed) {
      const banner = document.createElement("div");
      banner.className = "anvil-banner anvil-danger";
      banner.textContent =
        state.security.reasons[0] ?? "Remplissage bloqué par la politique anti-phishing.";
      this.popoverEl.appendChild(banner);
      return;
    }

    if (state.security.risk_level === "warn_http" || state.security.is_idn_punycode) {
      const warn = document.createElement("div");
      warn.className = "anvil-banner anvil-warn";
      warn.textContent =
        state.security.reasons[0] ?? "Vérifiez l'URL avant d'injecter vos identifiants.";
      this.popoverEl.appendChild(warn);
    }

    if (!state.unlocked) {
      const info = document.createElement("div");
      info.style.padding = "12px";
      info.style.color = "#A0A8B8";
      info.textContent =
        "Coffre verrouillé — ouvrez la popup Anvil (Ctrl+Shift+Y) pour déverrouiller.";
      this.popoverEl.appendChild(info);
      return;
    }

    const list = document.createElement("div");
    list.className = "anvil-list";
    if (state.items.length === 0) {
      const empty = document.createElement("div");
      empty.style.padding = "12px";
      empty.style.color = "#6C7385";
      empty.textContent = "Aucun identifiant correspondant à ce domaine.";
      list.appendChild(empty);
    } else {
      for (const item of state.items) {
        const row = document.createElement("button");
        row.type = "button";
        row.className = "anvil-item";

        const badge = document.createElement("div");
        badge.className = "anvil-badge";
        badge.style.color = item.fallback_color;
        badge.textContent = item.fallback_initials;

        const textWrap = document.createElement("div");
        textWrap.style.minWidth = "0";
        textWrap.style.flex = "1";

        const tEl = document.createElement("div");
        tEl.style.fontWeight = "600";
        tEl.style.whiteSpace = "nowrap";
        tEl.style.overflow = "hidden";
        tEl.style.textOverflow = "ellipsis";
        tEl.textContent = item.title;

        const sEl = document.createElement("div");
        sEl.style.color = "#A0A8B8";
        sEl.style.fontSize = "11.5px";
        sEl.textContent = item.subtitle;

        textWrap.append(tEl, sEl);
        row.append(badge, textWrap);
        row.addEventListener("click", () => {
          void this.onPickItem(item.id).finally(() => this.closePopover());
        });
        list.appendChild(row);
      }
    }
    this.popoverEl.appendChild(list);
  }
}
