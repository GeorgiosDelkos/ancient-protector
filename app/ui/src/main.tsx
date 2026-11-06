import { render } from "solid-js/web";

import { App } from "./App.tsx";
import { Settings } from "./Settings.tsx";
import "./style.css";
import "./settings.css";

const root = document.querySelector("#root");
if (root === null) {
  throw new Error("index.html has no #root element");
}
// One page for both windows: the settings window opens it as index.html#settings.
const settings = window.location.hash === "#settings";
document.documentElement.classList.add(settings ? "in-settings" : "in-popover");
render(() => (settings ? <Settings /> : <App />), root);
