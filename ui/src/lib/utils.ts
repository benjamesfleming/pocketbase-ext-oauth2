/**
 * Converts and normalizes string into a sentence.
 *
 * @param  {String}  str
 * @param  {Boolean} [stopCheck]
 * @return {String}
 */
export function sentenize(str: string, stopCheck = true): string {
    if (typeof str !== "string") {
        return "";
    }

    str = str.trim().split("_").join(" ");
    if (str === "") {
        return str;
    }

    str = str[0].toUpperCase() + str.substring(1);

    if (stopCheck) {
        let lastChar = str[str.length - 1];
        if (lastChar !== "." && lastChar !== "?" && lastChar !== "!") {
            str += ".";
        }
    }

    return str
}

/**
* Redirects to a specified URL using a POST request with provided data.
* @param {string} location The target URL.
* @param {object} data The data to be sent as key-value pairs.
*/
export function postRedirect(location: string, data: Record<string, any>): void {
    // Create a form element
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = location;
    form.style.display = 'none'; // Hide the form from the user

    // Append hidden input fields for the data
    for (const key in data) {
        if (Object.prototype.hasOwnProperty.call(data, key)) {
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = key;
            input.value = data[key];
            form.appendChild(input);
        }
    }

    // Append the form to the document body and submit it
    document.body.appendChild(form);
    form.submit();
    // Optional: remove the form after submission
    // document.body.removeChild(form); 
}

export function base64UrlDecode(base64UrlString: string): string {
    let base64 = base64UrlString.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4) {
        base64 += "=";
    }
    const decodedBinaryString = atob(base64);
    const utf8Bytes = Uint8Array.from(decodedBinaryString, (c) => c.charCodeAt(0));
    const decodedString = new TextDecoder().decode(utf8Bytes);
    return decodedString;
}