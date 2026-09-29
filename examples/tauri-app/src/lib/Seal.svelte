<script>
import { open, remove, seal } from "@auvo/tauri-plugin-crypto-hw-api";

let identifier = $state("default");
let plaintext = $state("");
let sealed = $state("");
let opened = $state("");
let backing = $state("");
let status = $state("");

async function _seal() {
	try {
		const result = await seal(identifier, plaintext);
		sealed = result.sealed;
		backing = result.backing;
		status = "";
	} catch (error) {
		status = `${error}`;
	}
}

async function _open() {
	try {
		const result = await open(identifier, sealed);
		opened = result.plaintext;
		backing = result.backing;
		status = "";
	} catch (error) {
		status = `${error}`;
	}
}

async function _remove() {
	try {
		status = (await remove(identifier))
			? "Removed."
			: "There was nothing kept under that name.";
	} catch (error) {
		status = `${error}`;
	}
}
</script>

<div>
    <div class="column">
        <input placeholder="Name to keep it under..." bind:value={identifier} />
        <input placeholder="Something to keep..." bind:value={plaintext} />
    </div>
    <div class="row">
        <button onclick={_seal}>Seal</button>
        <button onclick={_open}>Open</button>
        <button onclick={_remove}>Remove</button>
    </div>
    <p class="long-text">{sealed}</p>
    <p class="long-text">{opened}</p>
    <p>{backing}</p>
    <p>{status}</p>
</div>
