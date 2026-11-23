import { mount } from "svelte";
import "@anvil/ui/tokens.css";
import PopupApp from "./PopupApp.svelte";

const target = document.getElementById("popup-app");
if (!target) {
  throw new Error("Missing #popup-app mount container");
}

mount(PopupApp, { target });
