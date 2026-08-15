// Dashboard JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Auto-refresh dashboard stats
    if (document.querySelector('.dashboard-container')) {
        setTimeout(() => window.location.reload(), 60000);
    }
    
    // Update unread notification count
    updateUnreadCount();
    
    // Check for browser notifications
    if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission();
    }
});

// Update notification count
function updateUnreadCount() {
    fetch('/notifications/unread-count/')
        .then(response => response.json())
        .then(data => {
            const badge = document.getElementById('notification-badge');
            if (badge) {
                if (data.count > 0) {
                    badge.textContent = data.count;
                    badge.style.display = 'inline-block';
                } else {
                    badge.style.display = 'none';
                }
            }
        });
}

// Show browser notification
function showBrowserNotification(title, message) {
    if ('Notification' in window && Notification.permission === 'granted') {
        new Notification(title, {
            body: message,
            icon: '/static/img/icon.png'
        });
    }
}
