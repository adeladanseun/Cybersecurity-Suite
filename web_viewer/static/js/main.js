// Main JavaScript for CyberSecurity Suite Web Viewer

// Auto-dismiss alerts after 5 seconds
document.addEventListener('DOMContentLoaded', function() {
    const alerts = document.querySelectorAll('.alert');
    
    alerts.forEach(function(alert) {
        setTimeout(function() {
            alert.classList.remove('show');
            setTimeout(function() {
                alert.remove();
            }, 300);
        }, 5000);
    });
});

// Enable tooltips
document.addEventListener('DOMContentLoaded', function() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    const tooltipList = tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});

// Confirm before destructive actions
function confirmAction(message) {
    return confirm(message || 'Are you sure you want to proceed?');
}

// Format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Format date
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Update notification count on page load
function updateNotificationBadge() {
    fetch('/notifications/unread-count/', {
        method: 'GET',
        credentials: 'same-origin',
        headers: {
            'X-Requested-With': 'XMLHttpRequest',
        },
    })
    .then(response => {
        if (response.redirected) {
            // Not authenticated - hide badge
            document.getElementById('notification-badge').style.display = 'none';
            return;
        }
        return response.json();
    })
    .then(data => {
        const badge = document.getElementById('notification-badge');
        if (badge && data) {
            if (data.count > 0) {
                badge.textContent = data.count;
                badge.style.display = 'inline-block';
            } else {
                badge.style.display = 'none';
            }
        }
    })
    .catch(error => {
        console.log('Notification badge update skipped:', error);
    });
}

document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('notification-badge')) {
        updateNotificationBadge();
    }
});