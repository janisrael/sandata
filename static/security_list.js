// Security List Page - Advanced Options Handler

document.addEventListener('DOMContentLoaded', () => {
    loadAdvancedOptions();
    initAdvancedOptionsSave();
});

// Load saved advanced options from localStorage
function loadAdvancedOptions() {
    const savedOptions = localStorage.getItem('advancedScanOptions');
    
    if (savedOptions) {
        try {
            const options = JSON.parse(savedOptions);
            
            // Set checkbox states
            if (options.sqlInjection) {
                document.getElementById('adv-sql-injection').checked = true;
            }
            if (options.xssDetection) {
                document.getElementById('adv-xss-detection').checked = true;
            }
            if (options.pluginVuln) {
                document.getElementById('adv-plugin-vuln').checked = true;
            }
            if (options.subdomainEnum) {
                document.getElementById('adv-subdomain-enum').checked = true;
            }
            if (options.portScan) {
                document.getElementById('adv-port-scan').checked = true;
            }
            if (options.directoryBruteforce) {
                document.getElementById('adv-directory-bruteforce').checked = true;
            }
            if (options.apiDiscovery) {
                document.getElementById('adv-api-discovery').checked = true;
            }
            if (options.s3BucketCheck) {
                document.getElementById('adv-s3-bucket-check').checked = true;
            }
        } catch (e) {
            console.error('Error loading advanced options:', e);
        }
    }
}

// Save advanced options to localStorage
function initAdvancedOptionsSave() {
    const saveButton = document.getElementById('save-advanced-options');
    
    saveButton.addEventListener('click', () => {
        const options = {
            sqlInjection: document.getElementById('adv-sql-injection').checked,
            xssDetection: document.getElementById('adv-xss-detection').checked,
            pluginVuln: document.getElementById('adv-plugin-vuln').checked,
            subdomainEnum: document.getElementById('adv-subdomain-enum').checked,
            portScan: document.getElementById('adv-port-scan').checked,
            directoryBruteforce: document.getElementById('adv-directory-bruteforce').checked,
            apiDiscovery: document.getElementById('adv-api-discovery').checked,
            s3BucketCheck: document.getElementById('adv-s3-bucket-check').checked
        };
        
        // Save to localStorage
        localStorage.setItem('advancedScanOptions', JSON.stringify(options));
        
        // Show success notification
        showNotification('Advanced scan options saved successfully!', 'success');
        
        // Count enabled options
        const enabledCount = Object.values(options).filter(v => v).length;
        
        if (enabledCount > 0) {
            showNotification(`${enabledCount} advanced test(s) enabled. They will be included in all scans.`, 'info');
        }
    });
}

// Simple notification function
function showNotification(message, type) {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <span class="material-icons-round">${type === 'success' ? 'check_circle' : 'info'}</span>
        <span>${message}</span>
    `;
    
    document.body.appendChild(notification);
    
    // Trigger animation
    setTimeout(() => notification.classList.add('show'), 10);
    
    // Remove after 3 seconds
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

