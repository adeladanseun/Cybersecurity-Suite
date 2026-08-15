// Target management JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Auto-detect target type
    const addressInput = document.getElementById('id_address');
    const typeSelect = document.getElementById('id_type');
    
    if (addressInput && typeSelect) {
        addressInput.addEventListener('blur', function() {
            const address = addressInput.value.trim();
            
            if (address && typeSelect.value === '') {
                // Simple detection
                let detectedType = '';
                
                if (address.includes('/')) {
                    detectedType = 'cidr';
                } else if (address.startsWith('http://') || address.startsWith('https://')) {
                    detectedType = 'url';
                } else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(address)) {
                    detectedType = 'ip';
                } else if (address.includes('.')) {
                    detectedType = 'domain';
                } else {
                    detectedType = 'hostname';
                }
                
                if (detectedType) {
                    typeSelect.value = detectedType;
                }
            }
        });
    }
});
