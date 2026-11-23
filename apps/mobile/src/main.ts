import { mount } from "svelte";
import "@anvil/ui/tokens.css";
import App from "./App.svelte";

const target = document.getElementById("mobile-app");
if (!target) {
  throw new Error("Missing #mobile-app mount container");
}

mount(App, { target });
