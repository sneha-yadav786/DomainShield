document.addEventListener("DOMContentLoaded", () => {

    // -----------------------------------------
    // DOM Elements
    // -----------------------------------------

    const analyzeButton =
        document.getElementById("analyze-btn");

    const websiteName =
        document.getElementById("website-name");

    const websiteUrl =
        document.getElementById("website-url");

    const riskScore =
        document.getElementById("risk-score");

    const statusText =
        document.getElementById("status-text");

    const statusDescription =
        document.getElementById(
            "status-description"
        );

    const securityChecks =
        document.getElementById(
            "security-checks"
        );

    const reasonsSection =
        document.getElementById(
            "reasons-section"
        );

    const reasonsList =
        document.getElementById(
            "reasons-list"
        );


    // -----------------------------------------
    // Get Current Tab
    // -----------------------------------------

    chrome.tabs.query(
        {
            active: true,
            currentWindow: true
        },

        async (tabs) => {

            if (!tabs || !tabs[0]) {

                showError(
                    "Unable to access current tab."
                );

                return;
            }


            const url = tabs[0].url;


            if (!url) {

                showError(
                    "Unable to detect website URL."
                );

                return;
            }


            // Show URL in popup

            try {

                const currentUrl =
                    new URL(url);

                websiteName.textContent =
                    currentUrl.hostname;

                websiteUrl.textContent =
                    url;

            }

            catch (error) {

                websiteName.textContent =
                    "Unknown website";

                websiteUrl.textContent =
                    url;

            }


            // Automatically analyze website

            await analyzeWebsite(url);

        }
    );


    // -----------------------------------------
    // Analyze Button
    // -----------------------------------------

    analyzeButton.addEventListener(
        "click",
        async () => {

            chrome.tabs.query(
                {
                    active: true,
                    currentWindow: true
                },

                async (tabs) => {

                    if (!tabs || !tabs[0]) {

                        showError(
                            "Unable to access current tab."
                        );

                        return;
                    }


                    const url = tabs[0].url;


                    if (!url) {

                        showError(
                            "Website URL not found."
                        );

                        return;
                    }


                    await analyzeWebsite(url);

                }
            );

        }
    );


    // -----------------------------------------
    // Analyze Website
    // -----------------------------------------

    async function analyzeWebsite(url) {

        setLoadingState();


        try {

            const response =
                await fetch(
                    "http://127.0.0.1:8000/api/analyze/",
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body: JSON.stringify({
                            url: url
                        })
                    }
                );


            // ---------------------------------
            // Check HTTP response
            // ---------------------------------

            if (!response.ok) {

                let errorMessage =
                    "Backend request failed.";

                try {

                    const errorData =
                        await response.json();

                    if (errorData.error) {

                        errorMessage =
                            errorData.error;

                    }

                }

                catch (error) {

                    console.log(
                        "Could not read error response."
                    );

                }


                throw new Error(
                    errorMessage
                );

            }


            // ---------------------------------
            // Convert response to JSON
            // ---------------------------------

            const data =
                await response.json();


            console.log(
                "PhishGuard API Response:",
                data
            );


            // ---------------------------------
            // Update UI
            // ---------------------------------

            updateUI(data);

        }

        catch (error) {

            console.error(
                "PhishGuard Error:",
                error
            );


            showError(
                error.message ||
                "Unable to connect to backend."
            );

        }

    }


    // -----------------------------------------
    // Loading State
    // -----------------------------------------

    function setLoadingState() {

        analyzeButton.disabled = true;

        analyzeButton.innerHTML =
            "⏳ Analyzing...";


        riskScore.textContent =
            "--";


        statusText.textContent =
            "Analyzing website...";


        statusDescription.textContent =
            "Checking URL characteristics.";


        securityChecks.innerHTML = `
            <div class="check-item">

                <span class="check-icon">
                    •
                </span>

                <span>
                    Running security checks...
                </span>

            </div>
        `;


        reasonsSection.style.display =
            "none";

    }


    // -----------------------------------------
    // Update UI with Backend Response
    // -----------------------------------------

    function updateUI(data) {

        // Risk score

        riskScore.textContent =
            data.risk_score;


        // Status

        statusText.textContent =
            data.status_text;


        // Description

        statusDescription.textContent =
            data.description;


        // Risk colors

        updateRiskColor(
            data.status
        );


        // Security checks

        renderChecks(
            data.checks || []
        );


        // Reasons

        renderReasons(
            data.reasons || []
        );


        // Enable button

        analyzeButton.disabled =
            false;

        analyzeButton.innerHTML =
            "<span>🔍</span> Analyze Website";

    }


    // -----------------------------------------
    // Render Security Checks
    // -----------------------------------------

    function renderChecks(checks) {

        securityChecks.innerHTML = "";


        if (checks.length === 0) {

            securityChecks.innerHTML = `
                <div class="check-item">

                    <span class="check-icon">
                        •
                    </span>

                    <span>
                        No checks available.
                    </span>

                </div>
            `;

            return;
        }


        checks.forEach((check) => {

            const item =
                document.createElement("div");

            item.className =
                "check-item";


            const icon =
                document.createElement("span");

            icon.className =
                "check-icon";


            const text =
                document.createElement("span");


            text.textContent =
                check.name;


            // Safe

            if (check.status === "safe") {

                icon.textContent =
                    "✓";

            }


            // Warning

            else {

                icon.textContent =
                    "⚠";

                icon.classList.add(
                    "warning-icon"
                );

            }


            item.appendChild(icon);

            item.appendChild(text);

            securityChecks.appendChild(
                item
            );

        });

    }


    // -----------------------------------------
    // Render Detection Reasons
    // -----------------------------------------

    function renderReasons(reasons) {

        reasonsList.innerHTML = "";


        if (reasons.length === 0) {

            reasonsSection.style.display =
                "none";

            return;
        }


        reasonsSection.style.display =
            "block";


        reasons.forEach((reason) => {

            const item =
                document.createElement("div");

            item.className =
                "reason-item";


            item.textContent =
                "⚠ " + reason;


            reasonsList.appendChild(
                item
            );

        });

    }


    // -----------------------------------------
    // Risk Color
    // -----------------------------------------

    function updateRiskColor(status) {

        const resultCard =
            document.querySelector(
                ".result-card"
            );

        const riskCircle =
            document.querySelector(
                ".risk-circle"
            );


        // Reset classes

        resultCard.classList.remove(
            "safe-result",
            "warning-result",
            "danger-result"
        );


        riskCircle.classList.remove(
            "safe-circle",
            "warning-circle",
            "danger-circle"
        );


        statusText.classList.remove(
            "safe-text",
            "warning-text",
            "danger-text"
        );


        // SAFE

        if (status === "safe") {

            resultCard.classList.add(
                "safe-result"
            );

            riskCircle.classList.add(
                "safe-circle"
            );

            statusText.classList.add(
                "safe-text"
            );

        }


        // SUSPICIOUS

        else if (
            status === "suspicious"
        ) {

            resultCard.classList.add(
                "warning-result"
            );

            riskCircle.classList.add(
                "warning-circle"
            );

            statusText.classList.add(
                "warning-text"
            );

        }


        // HIGH RISK

        else {

            resultCard.classList.add(
                "danger-result"
            );

            riskCircle.classList.add(
                "danger-circle"
            );

            statusText.classList.add(
                "danger-text"
            );

        }

    }


    // -----------------------------------------
    // Error State
    // -----------------------------------------

    function showError(message) {

        riskScore.textContent =
            "--";


        statusText.textContent =
            "Analysis unavailable";


        statusDescription.textContent =
            message;


        securityChecks.innerHTML = `
            <div class="check-item">

                <span class="check-icon warning-icon">
                    ⚠
                </span>

                <span>
                    Backend connection required
                </span>

            </div>`
        ;


        reasonsSection.style.display =
            "none";


        analyzeButton.disabled =
            false;


        analyzeButton.innerHTML =
            "<span>🔍</span> Analyze Website";

    }

});