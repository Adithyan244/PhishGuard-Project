document.addEventListener('DOMContentLoaded', function() {
    const scanBtn = document.getElementById('scan-btn');
    const urlDisplay = document.getElementById('current-url');
    const resultDiv = document.getElementById('result');
    const statusText = document.getElementById('status-text');
    const riskScore = document.getElementById('risk-score')
    let targetUrl = "";
    // Ask chrome for the URL of the active tab
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        targetUrl = tabs[0].url;
        urlDisplay.textContent = targetUrl.length > 50 ? targetUrl.substring(0, 50) + "..." : targetUrl;
    });
    // When the user clicks the Scan Button
    scanBtn.addEventListener('click', async function(){
        scanBtn.textContent = "Analyzing Threat Intel...";
        scanBtn.disabled = true;
        resultDiv.style.display = "none";
        try{
            //Ping the Python FastAPI Server!
            const response = await fetch('http://127.0.0.1:8000/scan',{
                method: 'POST',
                headers: {
                    'Content-Type' : 'application/json'
                },
                body: JSON.stringify({ url: targetUrl })
            });
            if(!response.ok) throw new Error("API server offline or error.");
            const data = await response.json();
            //Update the UI based on AI's prediction
            resultDiv.style.display = "block";
            statusText.textContent = data.status === "MALICIOUS" ? "🚨THREAT DETECTED" : "✅ SAFE TO BROWSE";
            riskScore.textContent = `AI Confidence: ${data.risk_score_percentage.toFixed(2)}%`;
            if (data.status === "MALICIOUS") {
                resultDiv.className = "danger";
            } else {
                resultDiv.className = "safe";
            }
        } catch (error) {
            resultDiv.style.display = "block";
            resultDiv.className = "danger";
            statusText.textContent = "Connection Error";
            riskScore.textContent = "Is your Python server running?";
        } finally {
            scanBtn.textContent = "Scan Current Page";
            scanBtn.disabled = false;
        }
    });
});