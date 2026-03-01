// Main Jailbreak Function

window.script_loaded = 0;

// mostly used to yield to the GC. marking is concurrent but collection isn't
// yielding also lets the DOM update. which is useful since we use the DOM for
// logging and we loop when waiting for a collection to occur
function sleep(ms=0) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function getScript(source) {
  return new Promise((resolve, reject) => {
    const gs = document.createElement('script');
    gs.src = source;
    gs.async = false;
    gs.onload = () => resolve();
    gs.onerror = () => reject(new Error("Script load failed: " + source));
    document.body.appendChild(gs);
  });
}

async function loadScript(script_js) {
  window.script_loaded = 0;
  await getScript(script_js);
  // Wait for script to be loaded
  while (window.script_loaded < 1) {
    await sleep(50); // Wait 50ms
  }
}

async function doJailBreak() {
  var jb_step_status;
  if (config_target === 0x505) { // 5.05
    window.log("Starting 5.05 Exploit...");
    // 5.05 exploit is implemented inside index.html to maintain strict ES5 compatibility
    //  and avoid ES6 parsing issues on legacy WebKit
    window.log("\nYou should not be here!!!", "red");
  } else if ((config_target >= 0x670) && (config_target < 0x700)) { // 6.70 to 6.72
    if (window.entrypoint672_result < 1) {
      window.log("An error occured during Bad Hoist Entrypoint\nPlease refresh page and try again...", "red");
      return;
    }
    else
      window.log("Bad Hoist Entrypoint succeeded");
    if (window.exploitsetup672_result < 1) {
      window.log("An error occured during Exploit Setup\nPlease refresh page and try again...", "red");
      return;
    }
    else
      window.log("Exploit Setup complete\n");
    window.log("Starting 6.7x Kernel Exploit...");
    await sleep(200); // Wait 200ms
    await loadScript('672kexploit.js');
    var result = KernelExploit672();
    if (result === 0 || result === 91) {
      window.log("\nKernel exploit succeeded", "green");
      getPayload672("payload.bin");
      window.log("Homebrew Enabler loaded", "green");
      window.log("\nBad Hoist by Fire30, 6.7x Kernel Exploit by Sleirsgoevy");
    } else if (result === 179) {
      window.log("\nAlready jailbroken, no need to re-jailbrake", "green");
    } else {
      window.log("\nAn error occured during Kernel Exploit\nPlease restart console and try again...", "red");
    }
  } else if ((config_target >= 0x700) && (config_target < 0x1000)) { // 7.00 to 9.60
    await loadScript('psfree_lapse_helpers.js');
    await loadScript('psfree.js');
    Init_Globals();
    jb_step_status = await doPSFreeExploit();
    if (jb_step_status !== 1) return;
    window.log("Starting Lapse Kernel Exploit...");
    await sleep(200); // Wait 200ms
    await loadScript('kpatches.js');
    await loadScript('lapse.js');
    jb_step_status = await doLapseExploit();
    if (jb_step_status !== 1) return;
    await sleep(500); // Wait 500ms
    // Inject HEN payload
    jb_step_status = await PayloadLoader("payload.bin"); // Read payload from .bin file
    if (jb_step_status !== 1) {
      window.log("Failed to load HEN!\nPlease restart console and try again...", "red");
      return;
    }
    window.log("Homebrew Enabler loaded", "green");
    window.log("\nPSFree & Lapse exploit with AIO fixes by ABC");
  }
  else {
    window.log("Kernel Exploit not implemented!", "red");
  }
}
