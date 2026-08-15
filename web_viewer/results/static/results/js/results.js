// Results viewing JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Auto-refresh results if there are active scans
    const hasActiveScans = document.querySelector('.badge.bg-running');
    
    if (hasActiveScans) {
        setTimeout(() => window.location.reload(), 5000);
    }
});

// Filter results client-side
function filterTable(input, tableId) {
    const filter = input.value.toLowerCase();
    const table = document.getElementById(tableId);
    const rows = table.getElementsByTagName('tr');
    
    for (let i = 1; i < rows.length; i++) {
        const row = rows[i];
        const text = row.textContent.toLowerCase();
        
        if (text.includes(filter)) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    }
}
