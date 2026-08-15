// Report management JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Check for generating reports
    const generatingBadges = document.querySelectorAll('.badge.bg-generating');
    
    if (generatingBadges.length > 0) {
        setTimeout(() => window.location.reload(), 5000);
    }
});
