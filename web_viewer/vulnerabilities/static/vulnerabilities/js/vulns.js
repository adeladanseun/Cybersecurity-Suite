// Vulnerability management JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Auto-refresh dashboard stats if on dashboard page
    const dashboard = document.querySelector('.vuln-dashboard');
    
    if (dashboard) {
        setTimeout(() => window.location.reload(), 30000); // Refresh every 30s
    }
});

// Update status via AJAX
function updateVulnStatus(vulnId, status) {
    fetch(`/vulnerabilities/${vulnId}/update-status/`, {
        method: 'POST',
        headers: {
            'X-CSRFToken': getCookie('csrftoken'),
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Requested-With': 'XMLHttpRequest',
        },
        body: `status=${status}`,
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            location.reload();
        }
    });
}

// Get CSRF token
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}
