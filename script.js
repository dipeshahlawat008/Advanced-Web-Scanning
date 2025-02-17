// Tab switching functionality
function switchTab(tabId) {
    // Hide all tab contents
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });

    // Deactivate all tab buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });

    // Show selected tab content and activate button
    document.getElementById(tabId).classList.add('active');
    event.target.classList.add('active');
}

function showResult(resultId) {
    // Hide all result contents
    document.querySelectorAll('.result-content').forEach(content => {
        content.classList.remove('active');
    });

    // Deactivate all result tab buttons
    document.querySelectorAll('.result-tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });

    // Show selected result content
    document.getElementById(resultId).classList.add('active');
    event.target.classList.add('active');
}

function updateProgress(progress) {
    document.getElementById('scanProgress').style.width = `${progress}%`;
}

function startUrlScan() {
    const url = document.getElementById('urlInput').value;
    if (!url) {
        alert('Please enter a URL');
        return;
    }

    // Get selected options
    const options = {
        crawlPages: document.getElementById('crawlPages').checked,
        findDirs: document.getElementById('findDirs').checked,
        findPhp: document.getElementById('findPhp').checked,
        findEncoded: document.getElementById('findEncoded').checked
    };

    // Show results container
    document.getElementById('results').style.display = 'block';
    document.getElementById('statusBadge').textContent = 'Running';
    updateProgress(0);

    // Start the scan
    fetch('/start_scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            url: url,
            options: options
        })
    })
    .then(response => response.json())
    .then(data => {
        pollStatus();
    })
    .catch(error => {
        console.error('Error:', error);
        document.getElementById('statusBadge').textContent = 'Error';
    });
}

function startNetworkScan() {
    const target = document.getElementById('networkInput').value;
    if (!target) {
        alert('Please enter an IP or domain');
        return;
    }

    // Get selected options
    const options = {
        scanSubnet: document.getElementById('scanSubnet').checked,
        dnsEnum: document.getElementById('dnsEnum').checked,
        dirBuster: document.getElementById('dirBuster').checked,
        portScan: document.getElementById('portScan').checked,
        portRange: document.getElementById('portRange').value,
        wordlist: document.getElementById('wordlist').value
    };

    // Show results container
    document.getElementById('results').style.display = 'block';
    document.getElementById('statusBadge').textContent = 'Running';
    updateProgress(0);

    // Start the network scan
    fetch('/start_network_scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            target: target,
            options: options
        })
    })
    .then(response => response.json())
    .then(data => {
        pollStatus();
    })
    .catch(error => {
        console.error('Error:', error);
        document.getElementById('statusBadge').textContent = 'Error';
    });
}

function pollStatus() {
    fetch('/scan_status')
        .then(response => response.json())
        .then(data => {
            // Update counts
            document.getElementById('pagesCount').textContent = data.pages_found;
            document.getElementById('hiddenDirsCount').textContent = data.hidden_dirs;
            document.getElementById('phpFilesCount').textContent = data.php_files;
            document.getElementById('encodedDataCount').textContent = data.encoded_data;

            // Update network info
            document.getElementById('networkInfoData').textContent =
                JSON.stringify(data.network_info, null, 2);

            // Update progress bar
            updateProgress(data.progress || 0);

            // Update status badge
            if (data.is_complete) {
                document.getElementById('statusBadge').textContent = 'Complete';
            }

            // Continue polling if scan is not complete
            if (!data.is_complete) {
                setTimeout(pollStatus, 1000);
            }
        })
        .catch(error => console.error('Error:', error));
}

// Initialize tooltips or other UI elements
document.addEventListener('DOMContentLoaded', function() {
    // Add any initialization code here
});