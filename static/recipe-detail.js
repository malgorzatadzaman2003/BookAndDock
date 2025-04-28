// Toggle the 'checked' state for ingredients
document.querySelectorAll('.ingredient-checkbox').forEach(function(checkbox) {
    checkbox.addEventListener('change', function() {
        const label = this.nextElementSibling;
        if (this.checked) {
            label.style.textDecoration = 'line-through'; // Cross out the ingredient
        } else {
            label.style.textDecoration = 'none'; // Remove the line-through
        }
    });
});

// Mark instructions as 'checked' without crossing out
document.querySelectorAll('.instruction-checkbox').forEach(function(checkbox) {
    checkbox.addEventListener('change', function() {
        const label = this.nextElementSibling;
        if (this.checked) {
            label.style.fontWeight = 'bold'; // Mark as checked with bold text
        } else {
            label.style.fontWeight = 'normal'; // Remove bold styling
        }
    });
});

// --- NEW --- Toggle reply forms with smooth animation
document.addEventListener('DOMContentLoaded', function() {
    const replyForms = document.querySelectorAll('.reply-form');

    replyForms.forEach(form => {
        form.style.overflow = 'hidden';
        form.style.transition = 'max-height 0.3s ease, padding 0.3s ease';
        form.style.maxHeight = null;
        form.style.padding = "0";
    });
});

function toggleReplyForm(commentId) {
    const form = document.getElementById('reply-form-' + commentId);
    if (!form) return;

    // Close any other open reply forms first (optional: for cleaner UX)
    document.querySelectorAll('.reply-form').forEach(function(otherForm) {
        if (otherForm !== form) {
            otherForm.style.maxHeight = null;
            otherForm.style.padding = "0";
        }
    });

    // Toggle the clicked form
    if (form.style.maxHeight && form.style.maxHeight !== '0px') {
        form.style.maxHeight = null;
        form.style.padding = "0";
    } else {
        form.style.maxHeight = form.scrollHeight + "px";
        form.style.padding = "10px";
    }
}
