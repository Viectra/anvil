import { mount } from "svelte";
import "@anvil/ui/tokens.css";
import App from "./App.svelte";

const target = document.getElementById("app");
if (!target) {
  throw new Error("Missing #app mount container");
}

mount(App, { target });
