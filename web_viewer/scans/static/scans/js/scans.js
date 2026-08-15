// Scan management JavaScript

// Auto-update progress for active scans
document.addEventListener('DOMContentLoaded', function() {
    const progressBars = document.querySelectorAll('.progress-bar-animated');
    
    progressBars.forEach(function(bar) {
        const scanId = bar.dataset.scanId;
        
        if (scanId) {
            updateScanProgress(scanId, bar);
        }
    });
});

function updateScanProgress(scanId, progressBar) {
    fetch(`/scans/${scanId}/progress/`)
        .then(response => response.json())
        .then(data => {
            progressBar.style.width = data.progress + '%';
            progressBar.textContent = data.progress + '%';
            
            if (data.is_active) {
                setTimeout(() => updateScanProgress(scanId, progressBar), 3000);
            } else {
                // Reload page when scan finishes
                setTimeout(() => window.location.reload(), 1000);
            }
        })
        .catch(error => {
            console.error('Error updating progress:', error);
        });
}
