// Main page elements
const scanButton = document.querySelector("#scan-button");
const scanStatus = document.querySelector("#status");
const errorMessage = document.querySelector("#error");
const resultsSection = document.querySelector("#result-section");
const target = document.querySelector("#target");
const resultsList = document.querySelector("#result-list");

// Delete old entries and hide the results section and error message before new scan
function clearResults() {
  resultsList.replaceChildren();
  resultsSection.hidden = true;
  errorMessage.hidden = true;
  errorMessage.textContent = "";
}

// Takes response, creates list for each port result, reveals results section via textContent
function showResults(scan) {
  target.textContent = `Detected public IP: ${scan.target}`;
  for (const result of scan.results) {
    const item = document.createElement("li");
    const state = document.createElement("span");
    const service = document.createElement("span");

    state.className = "port-state";
    service.className = "service";

    // Display the port number and its state (open/closed) and the service name
    state.textContent = `Port ${result.port}: ${result.state}`;
    service.textContent = ` — ${result.service}`;
    item.append(state, service);
    resultsList.append(item);
  }
  resultsSection.hidden = false;
}

// Starts the scan to the backend
async function startScan() {
  clearResults();
  scanButton.disabled = true;
  scanStatus.textContent = "Scanning the detected public IP. This can take up to two minutes.";

  try {
    // Send a POST request your relative address to initiate the scan
    const response = await fetch("/api/scan", { method: "POST" });
    const body = await response.json();
    if (!response.ok || !body.ok) {
      throw new Error(body.error || "The scan could not be completed.");
    }
    // Display the results in the UI
    showResults(body);
    scanStatus.textContent = "Scan complete.";

    //log the results to the console for debugging purposes
  } catch (error) {
    scanStatus.textContent = "Scan did not complete.";
    errorMessage.textContent = error instanceof Error ? error.message : "The scan could not be completed.";
    errorMessage.hidden = false;
  } finally {
    scanButton.disabled = false;
  }
}

scanButton.addEventListener("click", startScan);
