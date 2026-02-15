export type Toast = {
    id: number;
    type: string;
    message: string;
    alertClass: string;
    iconClass: string;
};

export type ToastStore = {
    toasts: Toast[];

    addToast:    (type: string, message: string, duration?: number) => void;
    removeToast: (id: number) => void;
};

export default {
    toasts: [],

    /**
     * Adds a toast notification to the store.
     *
     * @param {string} type - The type of the toast (e.g., "info", "success", "warning", "error").
     * @param {string} message - The message to be displayed in the toast.
     * @param {number} [duration=4000] - The duration (in milliseconds) for which the toast should be displayed before automatically removing it.
     */
    addToast(type: string, message: string, duration = 4000) {
        const id = Date.now() + Math.random();
        const alertClass = {
            info:    "alert-info",
            success: "alert-success",
            warning: "alert-warning",
            error:   "alert-danger",
        }[type] || "";
        const iconClass = {
            info:    "ri-information-line",
            success: "ri-checkbox-circle-line",
            warning: "ri-error-warning-line",
            error:   "ri-alert-line",
        }[type] || "";
        this.toasts.push({ id, type, message, alertClass, iconClass });
        setTimeout(() => {
            this.removeToast(id);
        }, duration);
    },

    /**
     * Removes a toast notification from the store by its ID.
     *
     * @param {number} id - The unique identifier of the toast to be removed.
     */
    removeToast(id: number) {
        this.toasts = this.toasts.filter((t) => t.id !== id);
    },
} as ToastStore;