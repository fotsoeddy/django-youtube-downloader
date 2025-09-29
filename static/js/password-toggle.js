class PasswordToggle {
    constructor() {
        this.eyeOpenSVG = `
            <svg class="w-5 h-5 text-gray-800" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="none" viewBox="0 0 24 24">
                <path stroke="currentColor" stroke-width="2" d="M21 12c0 1.2-4.03 6-9 6s-9-4.8-9-6c0-1.2 4.03-6 9-6s9 4.8 9 6Z"/>
                <path stroke="currentColor" stroke-width="2" d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z"/>
            </svg>
        `;
        this.eyeClosedSVG = `
            <svg class="w-5 h-5 text-gray-800" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" width="24" height="24" fill="none" viewBox="0 0 24 24">
                <path stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.933 13.909A4.357 4.357 0 0 1 3 12c0-1 4-6 9-6m7.6 3.8A5.068 5.068 0 0 1 21 12c0 1-3 6-9 6-.314 0-.62-.014-.918-.04M5 19 19 5m-4 7a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z"/>
            </svg>
        `;
        this.init();
    }

    init() {
        // Find all password input fields
        const passwordInputs = document.querySelectorAll('input[type="password"]:not([type="hidden"]):not(.hidden):not([hidden="hidden"])');
        passwordInputs.forEach(input => this.setupPasswordToggle(input));
    }

    setupPasswordToggle(input) {
        // Check if the input is already wrapped to avoid duplicates
        if (input.parentElement.classList.contains('password-toggle-wrapper')) return;

        // Create a wrapper div with relative positioning
        const wrapper = document.createElement('div');
        wrapper.className = 'password-toggle-wrapper';
        wrapper.style.position = 'relative';

        // Move the input into the wrapper
        input.parentElement.insertBefore(wrapper, input);
        wrapper.appendChild(input);

        // Create the toggle span
        const toggleSpan = document.createElement('span');
        toggleSpan.className = 'password-toggle';
        toggleSpan.style.position = 'absolute';
        toggleSpan.style.right = '0.75rem';
        toggleSpan.style.top = '50%';
        toggleSpan.style.transform = 'translateY(-50%)';
        toggleSpan.style.cursor = 'pointer';
        toggleSpan.style.color = '#6b7280';
        toggleSpan.innerHTML = this.eyeClosedSVG;

        // Add hover effect
        toggleSpan.addEventListener('mouseover', () => {
            toggleSpan.style.color = '#0b5e65';
        });
        toggleSpan.addEventListener('mouseout', () => {
            toggleSpan.style.color = '#6b7280';
        });

        // Append the toggle span to the wrapper
        wrapper.appendChild(toggleSpan);

        // Add toggle event listener
        toggleSpan.addEventListener('click', () => this.togglePassword(input, toggleSpan));
    }

    togglePassword(input, toggleSpan) {
        const isPassword = input.type === 'password';
        input.type = isPassword ? 'text' : 'password';
        toggleSpan.innerHTML = isPassword ? this.eyeOpenSVG : this.eyeClosedSVG;
    }
}

// Initialize the class when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new PasswordToggle();
});
