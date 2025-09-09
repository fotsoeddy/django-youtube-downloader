/**
 * Modern Toast Manager with glass-morphism design and smooth animations
 * Uses a builder pattern for flexible configuration.
 * @class
 */
class ToastManager {
    constructor() {
        // Initialize toast container
        this.toastContainer = document.createElement('div');
        this.toastContainer.id = 'toast-container';
        document.body.appendChild(this.toastContainer);
        
        // Set default position
        this.setPosition('top-right');
        
        // Current config
        this.currentPosition = 'top-right';
        this.currentDuration = 4000;
        
        // Inject CSS styles
        this.injectStyles();
    }

    /**
     * Injects CSS styles for toast animations and layout.
     * @private
     */
    injectStyles() {
        const styles = `
            #toast-container {
                position: fixed;
                z-index: 10000;
                display: flex;
                flex-direction: column;
                gap: 16px;
                max-width: 400px;
                width: 100%;
                pointer-events: none;
            }
            
            #toast-container > * {
                pointer-events: auto;
            }
            
            /* Toast element styles */
            .toast {
                display: flex;
                align-items: center;
                width: 100%;
                padding: 16px;
                border-radius: 12px;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.15);
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                color: #333;
                position: relative;
                overflow: hidden;
                transition: transform 0.3s ease, opacity 0.3s ease;
            }
            
            .toast::before {
                content: '';
                position: absolute;
                left: 0;
                top: 0;
                height: 100%;
                width: 6px;
            }
            
            .toast-success::before {
                background: linear-gradient(to bottom, #00b09b, #96c93d);
            }
            
            .toast-error::before {
                background: linear-gradient(to bottom, #ff416c, #ff4b2b);
            }
            
            .toast-warning::before {
                background: linear-gradient(to bottom, #ff9800, #ffc107);
            }
            
            .toast-info::before {
                background: linear-gradient(to bottom, #2196f3, #21cbf3);
            }
            
            .toast-icon {
                margin-right: 15px;
                font-size: 24px;
                display: flex;
                align-items: center;
                justify-content: center;
                width: 36px;
                height: 36px;
                border-radius: 50%;
                flex-shrink: 0;
            }
            
            .toast-success .toast-icon {
                color: #00b09b;
                background-color: rgba(0, 176, 155, 0.15);
            }
            
            .toast-error .toast-icon {
                color: #ff416c;
                background-color: rgba(255, 65, 108, 0.15);
            }
            
            .toast-warning .toast-icon {
                color: #ff9800;
                background-color: rgba(255, 152, 0, 0.15);
            }
            
            .toast-info .toast-icon {
                color: #2196f3;
                background-color: rgba(33, 150, 243, 0.15);
            }
            
            .toast-content {
                flex-grow: 1;
                padding-right: 15px;
            }
            
            .toast-title {
                font-weight: 600;
                margin-bottom: 4px;
                font-size: 16px;
            }
            
            .toast-message {
                font-size: 14px;
                opacity: 0.9;
            }
            
            .toast-close {
                background: none;
                border: none;
                font-size: 18px;
                cursor: pointer;
                color: #999;
                padding: 5px;
                border-radius: 50%;
                width: 32px;
                height: 32px;
                display: flex;
                align-items: center;
                justify-content: center;
                flex-shrink: 0;
            }
            
            .toast-close:hover {
                background-color: rgba(0, 0, 0, 0.05);
                color: #666;
            }
            
            .toast-progress {
                position: absolute;
                bottom: 0;
                left: 0;
                height: 4px;
                width: 100%;
                background-color: rgba(0, 0, 0, 0.1);
                overflow: hidden;
            }
            
            .toast-progress-bar {
                height: 100%;
                width: 100%;
                transform-origin: left;
            }
            
            .toast-success .toast-progress-bar {
                background: linear-gradient(to right, #00b09b, #96c93d);
            }
            
            .toast-error .toast-progress-bar {
                background: linear-gradient(to right, #ff416c, #ff4b2b);
            }
            
            .toast-warning .toast-progress-bar {
                background: linear-gradient(to right, #ff9800, #ffc107);
            }
            
            .toast-info .toast-progress-bar {
                background: linear-gradient(to right, #2196f3, #21cbf3);
            }
            
            /* Animation keyframes */
            @keyframes slideInRight {
                from { 
                    transform: translateX(100%); 
                    opacity: 0;
                }
                to { 
                    transform: translateX(0); 
                    opacity: 1;
                }
            }
            
            @keyframes slideOutRight {
                from { 
                    transform: translateX(0); 
                    opacity: 1;
                }
                to { 
                    transform: translateX(100%); 
                    opacity: 0;
                }
            }
            
            @keyframes slideInLeft {
                from { 
                    transform: translateX(-100%); 
                    opacity: 0;
                }
                to { 
                    transform: translateX(0); 
                    opacity: 1;
                }
            }
            
            @keyframes slideOutLeft {
                from { 
                    transform: translateX(0); 
                    opacity: 1;
                }
                to { 
                    transform: translateX(-100%); 
                    opacity: 0;
                }
            }
            
            @keyframes slideInTop {
                from { 
                    transform: translateY(-100%); 
                    opacity: 0;
                }
                to { 
                    transform: translateY(0); 
                    opacity: 1;
                }
            }
            
            @keyframes slideOutTop {
                from { 
                    transform: translateY(0); 
                    opacity: 1;
                }
                to { 
                    transform: translateY(-100%); 
                    opacity: 0;
                }
            }
            
            @keyframes slideInBottom {
                from { 
                    transform: translateY(100%); 
                    opacity: 0;
                }
                to { 
                    transform: translateY(0); 
                    opacity: 1;
                }
            }
            
            @keyframes slideOutBottom {
                from { 
                    transform: translateY(0); 
                    opacity: 1;
                }
                to { 
                    transform: translateY(100%); 
                    opacity: 0;
                }
            }
            
            @keyframes progress {
                from { transform: scaleX(1); }
                to { transform: scaleX(0); }
            }
            
            /* Animation classes */
            .animate-slide-in-right {
                animation: slideInRight 0.5s ease-out forwards;
            }
            
            .animate-slide-out-right {
                animation: slideOutRight 0.5s ease-in forwards;
            }
            
            .animate-slide-in-left {
                animation: slideInLeft 0.5s ease-out forwards;
            }
            
            .animate-slide-out-left {
                animation: slideOutLeft 0.5s ease-in forwards;
            }
            
            .animate-slide-in-top {
                animation: slideInTop 0.5s ease-out forwards;
            }
            
            .animate-slide-out-top {
                animation: slideOutTop 0.5s ease-in forwards;
            }
            
            .animate-slide-in-bottom {
                animation: slideInBottom 0.5s ease-out forwards;
            }
            
            .animate-slide-out-bottom {
                animation: slideOutBottom 0.5s ease-in forwards;
            }
            
            .animate-progress {
                animation: progress linear forwards;
            }
            
            /* Responsive adjustments */
            @media (max-width: 768px) {
                #toast-container {
                    max-width: 90%;
                }
            }
        `;
        
        const styleSheet = document.createElement('style');
        styleSheet.textContent = styles;
        document.head.appendChild(styleSheet);
        
        // Add Font Awesome if not already present
        if (!document.querySelector('link[href*="font-awesome"]')) {
            const fontAwesomeLink = document.createElement('link');
            fontAwesomeLink.rel = 'stylesheet';
            fontAwesomeLink.href = 'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css';
            document.head.appendChild(fontAwesomeLink);
        }
    }

    /**
     * Sets the position of the toast container.
     * @param {string} position - The position ('top-left', 'top-right', 'bottom-left', 'bottom-right').
     * @private
     */
    setPosition(position) {
        // Remove existing position classes
        this.toastContainer.classList.remove('top-right', 'top-left', 'bottom-right', 'bottom-left');
        
        // Apply new position
        this.toastContainer.classList.add(position);
        
        // Set custom properties for position
        switch (position) {
            case 'top-left':
                this.toastContainer.style.top = '20px';
                this.toastContainer.style.left = '20px';
                this.toastContainer.style.bottom = '';
                this.toastContainer.style.right = '';
                break;
            case 'top-right':
                this.toastContainer.style.top = '20px';
                this.toastContainer.style.right = '20px';
                this.toastContainer.style.bottom = '';
                this.toastContainer.style.left = '';
                break;
            case 'bottom-left':
                this.toastContainer.style.bottom = '20px';
                this.toastContainer.style.left = '20px';
                this.toastContainer.style.top = '';
                this.toastContainer.style.right = '';
                break;
            case 'bottom-right':
                this.toastContainer.style.bottom = '20px';
                this.toastContainer.style.right = '20px';
                this.toastContainer.style.top = '';
                this.toastContainer.style.left = '';
                break;
        }
        
        this.currentPosition = position;
    }

    /**
     * Creates a new ToastBuilder instance to configure a toast.
     * @returns {ToastBuilder} A new ToastBuilder instance.
     * @example
     * toastManager.buildToast()
     *     .setMessage('Operation successful!')
     *     .setType('success')
     *     .setPosition('bottom-right')
     *     .setDuration(6000)
     *     .show();
     */
    buildToast() {
        return new ToastBuilder(this);
    }

    /**
     * Shows a toast with the specified configuration.
     * @private
     * @param {Object} config - The toast configuration.
     * @param {string} config.message - The message to display.
     * @param {string} [config.type='info'] - The type of toast ('success', 'error', 'warning', 'info').
     * @param {string} [config.position='top-right'] - The position ('top-left', 'top-right', 'bottom-left', 'bottom-right').
     * @param {number} [config.duration=4000] - The duration of the progress bar and auto-close in milliseconds.
     */
    showToast(config) {
        const { message, type = 'info', position = 'top-right', duration = 4000 } = config;
        
        // Update position if needed
        if (position !== this.currentPosition) {
            this.setPosition(position);
        }
        
        const toastStyles = {
            success: {
                class: 'toast-success',
                icon: '<i class="fas fa-check-circle"></i>',
                title: 'Success'
            },
            error: {
                class: 'toast-error',
                icon: '<i class="fas fa-exclamation-circle"></i>',
                title: 'Error'
            },
            warning: {
                class: 'toast-warning',
                icon: '<i class="fas fa-exclamation-triangle"></i>',
                title: 'Warning'
            },
            info: {
                class: 'toast-info',
                icon: '<i class="fas fa-info-circle"></i>',
                title: 'Information'
            }
        };

        const style = toastStyles[type] || toastStyles.info;

        // Determine animation based on position
        let slideInAnimation, slideOutAnimation;
        switch (position) {
            case 'top-left':
                slideInAnimation = 'animate-slide-in-left';
                slideOutAnimation = 'animate-slide-out-left';
                break;
            case 'top-right':
                slideInAnimation = 'animate-slide-in-right';
                slideOutAnimation = 'animate-slide-out-right';
                break;
            case 'bottom-left':
                slideInAnimation = 'animate-slide-in-left';
                slideOutAnimation = 'animate-slide-out-left';
                break;
            case 'bottom-right':
                slideInAnimation = 'animate-slide-in-right';
                slideOutAnimation = 'animate-slide-out-right';
                break;
            default:
                slideInAnimation = 'animate-slide-in-right';
                slideOutAnimation = 'animate-slide-out-right';
        }

        // Create toast element
        const toast = document.createElement('div');
        toast.className = `toast ${style.class} ${slideInAnimation}`;
        
        // Set progress bar animation duration
        const progressDuration = `${duration}ms`;
        
        toast.innerHTML = `
            <div class="toast-icon">${style.icon}</div>
            <div class="toast-content">
                <div class="toast-title">${style.title}</div>
                <div class="toast-message">${message}</div>
            </div>
            <button class="toast-close">
                <i class="fas fa-times"></i>
            </button>
            <div class="toast-progress">
                <div class="toast-progress-bar animate-progress" style="animation-duration: ${progressDuration};"></div>
            </div>
        `;

        this.toastContainer.appendChild(toast);

        // Close button handler
        const closeBtn = toast.querySelector('.toast-close');
        closeBtn.addEventListener('click', () => {
            toast.classList.remove(slideInAnimation);
            toast.classList.add(slideOutAnimation);
            setTimeout(() => {
                if (toast.parentElement) {
                    toast.remove();
                }
            }, 500);
        });

        // Auto-close after specified duration
        setTimeout(() => {
            if (toast.parentElement) {
                toast.classList.remove(slideInAnimation);
                toast.classList.add(slideOutAnimation);
                setTimeout(() => {
                    if (toast.parentElement) {
                        toast.remove();
                    }
                }, 500);
            }
        }, duration);
    }

    /**
     * Closes all currently displayed toasts.
     * @example
     * toastManager.closeAllToasts();
     */
    closeAllToasts() {
        const toasts = this.toastContainer.querySelectorAll('.toast');
        toasts.forEach(toast => {
            const slideInAnimation = Array.from(toast.classList).find(cls => cls.startsWith('animate-slide-in'));
            let slideOutAnimation = 'animate-slide-out-right';
            
            if (slideInAnimation) {
                const direction = slideInAnimation.replace('animate-slide-in-', '');
                slideOutAnimation = `animate-slide-out-${direction}`;
            }

            toast.classList.remove(slideInAnimation);
            toast.classList.add(slideOutAnimation);
            setTimeout(() => {
                if (toast.parentElement) {
                    toast.remove();
                }
            }, 500);
        });
    }
}

/**
 * Builder class for configuring and displaying toasts fluently.
 * @class
 */
class ToastBuilder {
    /**
     * @param {ToastManager} manager - The ToastManager instance.
     */
    constructor(manager) {
        this.manager = manager;
        this.config = {
            message: '',
            type: 'info',
            position: 'top-right',
            duration: 4000 // Default duration: 4 seconds
        };
    }

    /**
     * Sets the toast message.
     * @param {string} message - The message to display.
     * @returns {ToastBuilder} This builder instance.
     */
    setMessage(message) {
        this.config.message = message;
        return this;
    }

    /**
     * Sets the toast type.
     * @param {string} type - The type of toast ('success', 'error', 'warning', 'info').
     * @returns {ToastBuilder} This builder instance.
     */
    setType(type) {
        this.config.type = type;
        return this;
    }

    /**
     * Sets the toast position.
     * @param {string} position - The position ('top-left', 'top-right', 'bottom-left', 'bottom-right').
     * @returns {ToastBuilder} This builder instance.
     */
    setPosition(position) {
        this.config.position = position;
        return this;
    }

    /**
     * Sets the duration of the toast progress bar and auto-close.
     * @param {number} duration - The duration in milliseconds.
     * @returns {ToastBuilder} This builder instance.
     */
    setDuration(duration) {
        this.config.duration = duration;
        return this;
    }

    /**
     * Shows the configured toast.
     * @example
     * toastManager.buildToast()
     *     .setMessage('Operation successful!')
     *     .setType('success')
     *     .setPosition('bottom-right')
     *     .setDuration(6000)
     *     .show();
     */
    show() {
        if (!this.config.message) {
            throw new Error('Toast message is required');
        }
        this.manager.showToast(this.config);
    }
}

// Export a singleton instance
const toastManager = new ToastManager();
window.toastManager = toastManager;